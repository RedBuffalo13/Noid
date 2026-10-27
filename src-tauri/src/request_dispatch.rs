//! Application-level dispatch for `P2PEvent::RequestReceived`.
//!
//! Every inbound request-response message lands here. The return value is
//! the acknowledgement decision: `Some(status)` answers the parked
//! `ResponseChannel` (the sender then clears its pending row), `None`
//! leaves the request unanswered so the sender's request times out and
//! the message is re-pended for retry — the "ack only after durable
//! processing" rule (audit TI-1/F10). The transport-level response is no
//! longer sent before persistence.

use tauri::Manager;
use uuid::Uuid;

use crate::p2p::{MessageType, NoidMessage, P2PCommand};
use crate::{safe_emit, AppState, BufferedInbound};

/// Process an inbound `NoidMessage` and decide whether to acknowledge it.
/// `Some("OK")`/`Some("DUPLICATE")` — respond to the sender; `None` — let
/// the request time out so the sender retries (not yet durable here).
pub(crate) async fn handle_request_received(
    handle: &tauri::AppHandle,
    from: &str,
    data: &NoidMessage,
) -> Option<&'static str> {
    // S23: field bounds — reject degenerate payloads before any processing.
    // Outbound content is capped at MAX_DHT_MESSAGE_SIZE plaintext; the
    // wire form additionally carries ratchet overhead + base64, and typed
    // variants carry wrapped payloads/avatars — 256 KiB is generous cover.
    if data.id.len() > 128 || data.content.len() > 256 * 1024 {
        log::warn!("Oversized NoidMessage field from {} — dropped", from);
        return None;
    }
    // S22: the inner `sender` field is sender-chosen plaintext — never trust
    // it over the Noise-authenticated `from`. Emit a normalized copy so the
    // frontend contract is consistent regardless of what the peer claimed.
    let mut wire = data.clone();
    wire.sender = from.to_string();
    match &data.msg_type {
        MessageType::Chat(content) => {
            let app_state = handle.state::<AppState>();
            // RC2: db snapshot, guard released before my_id/security locks.
            let db = app_state.db.lock().await.clone();
            let db = match db {
                Some(db) => db,
                // Pre-login: nothing durable — leave unanswered, the
                // sender's retry lands after login and persists then.
                None => return None,
            };
            let my_id = app_state.my_id.lock().await.clone();
            // S7: a peer with an established ratchet session sending
            // plaintext Chat is a downgrade — the outgoing path is
            // ratchet-only, so refuse it rather than persist a fake-E2EE
            // message into history.
            if app_state.ratchet_sessions.has_session(from).await {
                log::warn!(
                    "Plaintext Chat from {} rejected — ratchet session exists (downgrade?)",
                    from
                );
                return None;
            }
            // Phase 1.4: use data.id and check for duplicates
            let msg_id = data.id.clone();
            if db.message_exists(&msg_id).await.unwrap_or(false) {
                log::debug!("Skipping duplicate direct message {}", msg_id);
                return Some("DUPLICATE");
            }
            let encrypted_for_storage = {
                let security_guard = app_state.security.lock().await;
                security_guard.encrypt(content.as_bytes()).ok()
            };

            let persisted = match encrypted_for_storage {
                Some(enc) => {
                    let timestamp = data.timestamp.clone().unwrap_or_else(|| {
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    });
                    db.add_message_with_timestamp(&msg_id, from, &my_id, &enc, &timestamp)
                        .await
                        .is_ok()
                }
                None => false,
            };

            if !persisted {
                // Ack only when the write landed — a storage failure must
                // surface as a sender-side retry, not a fake delivery.
                return None;
            }
            // TI-22: emit the inner chat text in `data.content` — the
            // envelope's outer `content` field carries the serialized
            // typed payload, not what was persisted, so the UI previously
            // rendered a different string than history replays.
            wire.content = content.clone();
            safe_emit(handle, "chat-msg", serde_json::json!({"from": from, "data": wire}));
            // A23: reach the shade even with a frozen background WebView.
            crate::android_bridge::notify_new_message(handle, from);
            Some("OK")
        }
        MessageType::RatchetChat {
            ciphertext,
            header_dh_public,
            header_pn,
            header_n,
        } => {
            // Phase 3.5: Decrypt Double Ratchet encrypted message
            let app_state = handle.state::<AppState>();
            let msg_id = data.id.clone();

            // Check for duplicates — db snapshot, guard released before
            // session/security locks (RC2).
            let db = app_state.db.lock().await.clone();
            if let Some(ref db) = db {
                if db.message_exists(&msg_id).await.unwrap_or(false) {
                    log::debug!("Skipping duplicate ratchet message {}", msg_id);
                    return Some("DUPLICATE");
                }
            }

            let ratchet_msg = crate::security::RatchetMessage {
                header: crate::security::RatchetHeader {
                    dh_public: header_dh_public.clone(),
                    pn: *header_pn,
                    n: *header_n,
                },
                ciphertext: ciphertext.clone(),
            };

            // Lazily restore the session from DB — the send path already
            // does this; without it, messages redelivered after a restart
            // are undecryptable and silently dropped.
            if !app_state.ratchet_sessions.has_session(from).await {
                if let Some(ref db) = db {
                    let _ = app_state.ratchet_sessions.load_session(db, from).await;
                }
            }

            match app_state
                .ratchet_sessions
                .decrypt(from, &ratchet_msg)
                .await
            {
                Ok(plaintext_bytes) => {
                    app_state.ratchet_sessions.note_decrypt_success(from).await;
                    let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
                    log::debug!(
                        "Decrypted ratchet message from {}: {} bytes",
                        from,
                        plaintext_bytes.len()
                    );

                    // Decrypted but nowhere to persist (pre-login DB) —
                    // buffer for retry and leave the request unanswered.
                    let Some(ref db) = db else {
                        let mut buf = app_state.undecrypted_inbound.lock().await;
                        let total: usize = buf.values().map(|v| v.len()).sum();
                        let entry = buf.entry(from.to_string()).or_default();
                        if total < 500 && !entry.iter().any(|m| m.id == msg_id) {
                            entry.push(BufferedInbound {
                                id: msg_id.clone(),
                                msg: ratchet_msg.clone(),
                                timestamp: data.timestamp.clone(),
                            });
                        }
                        return None;
                    };

                    // MD-04: E2EE file payloads ride RatchetChat with a
                    // NOIDFILE1: marker — route them to the file inbox
                    // instead of the chat log. The ciphertext never
                    // touches `messages`, so a file does not pollute the
                    // conversation history.
                    if let Some(file_json) = plaintext.strip_prefix("NOIDFILE1:") {
                        let _ = app_state.ratchet_sessions.save_session(db, from).await;
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(file_json) {
                            match v.get("kind").and_then(|k| k.as_str()) {
                                Some("offer") => {
                                    let offer_id = v.get("offer_id").and_then(|x| x.as_str()).unwrap_or("");
                                    let name = v.get("file_name").and_then(|x| x.as_str()).unwrap_or("file");
                                    let size = v.get("file_size").and_then(|x| x.as_u64()).unwrap_or(0);
                                    let mut inbox = app_state.file_inbox.lock().await;
                                    crate::file_inbox::register_offer(
                                        &mut inbox,
                                        &format!("{}:{}", from, offer_id),
                                        name,
                                        size,
                                    );
                                    safe_emit(handle, "file-offer", serde_json::json!({
                                        "from": from,
                                        "offer_id": offer_id,
                                        "name": name,
                                        "size": size,
                                    }));
                                    crate::android_bridge::notify_new_message(handle, from);
                                }
                                Some("chunk") => {
                                    let offer_id = v.get("offer_id").and_then(|x| x.as_str()).unwrap_or("");
                                    let idx = v.get("chunk_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                                    let total = v.get("total_chunks").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                                    let b64 = v.get("data").and_then(|x| x.as_str()).unwrap_or("");
                                    if let Ok(chunk) = base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD, b64,
                                    ) {
                                        let mut inbox = app_state.file_inbox.lock().await;
                                        if let Some(path) = crate::file_inbox::ingest_chunk(
                                            &mut inbox,
                                            &format!("{}:{}", from, offer_id),
                                            idx,
                                            total,
                                            &chunk,
                                            &app_state.app_data_dir,
                                        ) {
                                            safe_emit(handle, "file-received", serde_json::json!({
                                                "from": from,
                                                "offer_id": offer_id,
                                                "path": path,
                                            }));
                                            crate::android_bridge::notify_new_message(handle, from);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        return Some("OK");
                    }

                    let my_id = app_state.my_id.lock().await.clone();
                    let encrypted_for_storage = {
                        let security_guard = app_state.security.lock().await;
                        security_guard.encrypt(&plaintext_bytes).ok()
                    };
                    let persisted = match encrypted_for_storage {
                        Some(enc) => {
                            let timestamp = data.timestamp.clone().unwrap_or_else(|| {
                                chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                            });
                            db.add_message_with_timestamp(&msg_id, from, &my_id, &enc, &timestamp)
                                .await
                                .is_ok()
                        }
                        None => false,
                    };
                    // Save ratchet state after decryption
                    let _ = app_state.ratchet_sessions.save_session(db, from).await;

                    if !persisted {
                        return None;
                    }

                    // Emit with decrypted content
                    let mut data_with_plaintext = data.clone();
                    data_with_plaintext.content = plaintext;
                    data_with_plaintext.msg_type =
                        MessageType::Chat(data_with_plaintext.content.clone());
                    safe_emit(
                        handle,
                        "chat-msg",
                        serde_json::json!({"from": from, "data": data_with_plaintext}),
                    );
                    crate::android_bridge::notify_new_message(handle, from);

                    // Decryption now works — flush any earlier buffered
                    // messages from this peer (e.g. pre-login redelivery).
                    if app_state
                        .undecrypted_inbound
                        .lock()
                        .await
                        .contains_key(from)
                    {
                        let h = handle.clone();
                        tokio::spawn(async move {
                            crate::retry_undecrypted_messages(&h).await;
                        });
                    }
                    Some("OK")
                }
                Err(e) => {
                    log::warn!("Failed to decrypt ratchet message from {}: {}", from, e);
                    // S5: a replayed ciphertext fails AEAD on an already-
                    // consumed position — that is not desync, don't count it.
                    let replay = app_state
                        .ratchet_sessions
                        .is_replay_message(from, &ratchet_msg)
                        .await;
                    if replay {
                        // RC11: "DUPLICATE" is only safe when the copy we
                        // decrypted earlier actually reached durable state —
                        // if that persist failed we answered None (sender
                        // re-pended) and this retry is the ONLY surviving
                        // copy; acking it would lose the body forever.
                        let already_stored = match db.as_ref() {
                            Some(db) => db.message_exists(&msg_id).await.unwrap_or(false),
                            None => false,
                        };
                        if already_stored {
                            log::debug!("Ignoring replayed ratchet message {} from {}", msg_id, from);
                            return Some("DUPLICATE");
                        }
                        log::warn!(
                            "Replay of {} from {} but no stored row — treating as unacknowledged",
                            msg_id, from
                        );
                        return None;
                    }
                    if app_state.ratchet_sessions.has_session(from).await {
                        // Session exists but decryption failed — count it;
                        // persistent failures mean diverged ratchet state
                        // that only a fresh X3DH handshake recovers.
                        let fails = app_state
                            .ratchet_sessions
                            .record_decrypt_failure(from)
                            .await;
                        if fails >= 3
                            && app_state.ratchet_sessions.should_rehandshake(from).await
                        {
                            log::info!(
                                "Ratchet desync with {} ({} failures) — re-handshaking",
                                from,
                                fails
                            );
                            if let Some(tx) = app_state.p2p() {
                                let _ = crate::send_p2p_cmd(&tx, P2PCommand::FetchPrekeyBundle {
                                        peer_id: from.to_string(),
                                    })
                                    .await;
                            }
                        }
                    } else {
                        // MD-09: a ciphertext with NO session is still a
                        // desync signal — the peer ratcheted on a session we
                        // lost/wiped; count it so three misses trigger the
                        // same FetchPrekeyBundle recovery as a broken one.
                        let fails = app_state
                            .ratchet_sessions
                            .record_decrypt_failure(from)
                            .await;
                        if fails >= 3
                            && app_state.ratchet_sessions.should_rehandshake(from).await
                        {
                            log::info!(
                                "No ratchet session for {} ({} cipher failures) — re-handshaking",
                                from, fails
                            );
                            if let Some(tx) = app_state.p2p() {
                                let _ = crate::send_p2p_cmd(&tx, P2PCommand::FetchPrekeyBundle {
                                        peer_id: from.to_string(),
                                    })
                                    .await;
                            }
                        }
                        // No usable session yet (DB still locked or never
                        // restored) — buffer for post-login retry instead
                        // of dropping the message permanently.
                        let mut buf = app_state.undecrypted_inbound.lock().await;
                        let total: usize = buf.values().map(|v| v.len()).sum();
                        let entry = buf.entry(from.to_string()).or_default();
                        if total < 500 && !entry.iter().any(|m| m.id == msg_id) {
                            entry.push(BufferedInbound {
                                id: msg_id.clone(),
                                msg: ratchet_msg.clone(),
                                timestamp: data.timestamp.clone(),
                            });
                            log::debug!(
                                "Buffered undecryptable message {} from {} for post-login retry",
                                msg_id,
                                from
                            );
                        }
                    }
                    // Not durable — no ack; sender retries via timeout/re-pend.
                    None
                }
            }
        }
        MessageType::X3DHInit {
            identity_public,
            ephemeral_public,
            one_time_prekey_id,
            identity_signature,
        } => {
            // Phase A.5: Receive X3DH handshake from peer —
            // shared with the mailbox retrieval path.
            crate::x3dh_dispatch::handle_x3dh_init(
                handle,
                from.to_string(),
                identity_public,
                ephemeral_public,
                one_time_prekey_id,
                identity_signature,
            )
            .await;
            Some("OK")
        }
        MessageType::Ping => {
            let app_state = handle.state::<AppState>();

            if let Some(tx) = app_state.p2p() {
                let my_id = app_state.my_id.lock().await.clone();
                let pong_msg = NoidMessage {
                    sender: my_id,
                    content: "pong".to_string(),
                    msg_type: MessageType::Pong,
                    timestamp: Some(
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ),
                    id: Uuid::new_v4().to_string(),
                };

                let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendMessage {
                        peer_id: from.to_string(),
                        msg: pong_msg,
                    })
                    .await;
            }

            safe_emit(handle, "peer-online", from);
            Some("OK")
        }
        MessageType::Pong => {
            safe_emit(handle, "peer-online", from);
            Some("OK")
        }
        MessageType::ContactRequest { .. } | MessageType::ContactAccept { .. } => {
            crate::contact_dispatch::dispatch_contact_message(handle, from, data).await;
            Some("OK")
        }
        MessageType::DHTAck {
            original_message_id,
        } => {
            log::debug!(
                "Received DHT ACK for message {} from {}",
                original_message_id,
                from
            );

            let app_state = handle.state::<AppState>();
            let db = app_state.db.lock().await.clone();
            if let Some(db) = db {
                // Scoped to (from, id) — a peer can only clear its own row.
                let _ = db
                    .delete_pending_message_by_id(from, original_message_id)
                    .await;
                log::debug!(
                    "Removed message {} from pending after ACK",
                    original_message_id
                );
            }
            Some("OK")
        }
        MessageType::PublicKeyExchange { public_key } => {
            // S2/S22: a low-order point yields a publicly-computable shared
            // secret — reject it before it ever lands in the key store.
            if crate::security::is_low_order_x25519(public_key) {
                log::warn!("Rejected low-order public key from {}", from);
                return None;
            }
            log::debug!("Received public key from peer {}", from);

            let app_state = handle.state::<AppState>();
            // Save key and decide whether to respond (avoid ping-pong)
            let should_respond = {
                let db_state = app_state.db.lock().await;
                if let Some(db) = db_state.as_ref() {
                    let differs = match db.get_contact_public_key(from).await {
                        Ok(Some(stored)) => stored != *public_key,
                        Ok(None) => true,
                        Err(_) => false,
                    };
                    let _ = db.save_contact_public_key(from, public_key.as_slice()).await;
                    log::debug!("Saved public key for peer {}", from);
                    differs
                } else {
                    false
                }
            };

            if should_respond {
                if let Some(tx) = app_state.p2p() {
                    let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendPublicKey {
                            peer_id: from.to_string(),
                        })
                        .await;
                    log::debug!(
                        "Responded with our public key to {} (key was new/different)",
                        from
                    );
                }
            }
            Some("OK")
        }
        MessageType::ReadReceipt { message_id } => {
            // S22: receipts/status must come from a peer we actually
            // converse with — otherwise any peer can spoof "read" markers.
            let app_state = handle.state::<AppState>();
            let known = app_state.ratchet_sessions.has_session(from).await || {
                let db_state = app_state.db.lock().await;
                match db_state.as_ref() {
                    Some(db) => db.is_contact(from).await.unwrap_or(false),
                    None => false,
                }
            };
            if !known {
                log::debug!("ReadReceipt from unknown peer {} — dropped", from);
                return None;
            }
            safe_emit(
                handle,
                "message-read",
                serde_json::json!({"from": from, "message_id": message_id}),
            );
            Some("OK")
        }
        MessageType::TypingIndicator => {
            let app_state = handle.state::<AppState>();
            let known = app_state.ratchet_sessions.has_session(from).await || {
                let db_state = app_state.db.lock().await;
                match db_state.as_ref() {
                    Some(db) => db.is_contact(from).await.unwrap_or(false),
                    None => false,
                }
            };
            if !known {
                log::debug!("TypingIndicator from unknown peer {} — dropped", from);
                return None;
            }
            safe_emit(handle, "typing-indicator", from);
            Some("OK")
        }
        MessageType::RoomInvite {
            room_id,
            wrapped_key,
        } => {
            if crate::room_control::apply_room_invite(handle, room_id, from, wrapped_key).await {
                Some("OK")
            } else {
                None
            }
        }
        MessageType::RoomInviteOffer {
            room_id,
            wrapped_meta,
        } => {
            if crate::room_control::apply_room_offer(handle, room_id, from, wrapped_meta).await {
                Some("OK")
            } else {
                None
            }
        }
        MessageType::RoomInviteAccept { room_id } => {
            crate::room_control::handle_room_invite_accept(handle, room_id, from).await;
            Some("OK")
        }
        MessageType::RoomInviteDecline { room_id } => {
            crate::room_control::handle_room_invite_decline(handle, room_id, from).await;
            Some("OK")
        }
        MessageType::RoomControl {
            room_id,
            wrapped_payload,
        } => {
            if crate::room_control::apply_room_control(handle, room_id, from, wrapped_payload)
                .await
            {
                Some("OK")
            } else {
                None
            }
        }
        MessageType::RoomChat { room_id, envelope } => {
            crate::room_control::apply_room_chat(handle, room_id, envelope).await;
            Some("OK")
        }
        // TI-15: the send path exists but receivers used to drop offers
        // and chunks into the catch-all. `data.content` is JSON — offers
        // carry `file_name`/`file_size`, chunks carry `chunk_index`/`data`
        // (base64). Complete transfers land under <app_data>/received/.
        MessageType::FileOffer { name, size, id } => {
            let meta: serde_json::Value = match serde_json::from_str(&data.content) {
                Ok(v) => v,
                Err(_) => return Some("OK"),
            };
            if let (Some(idx), Some(total), Some(b64)) = (
                meta.get("chunk_index").and_then(|v| v.as_u64()),
                meta.get("total_chunks").and_then(|v| v.as_u64()),
                meta.get("data").and_then(|v| v.as_str()),
            ) {
                let offer_id = meta.get("offer_id").and_then(|v| v.as_str()).unwrap_or(id);
                let chunk = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD, b64,
                ) {
                    Ok(c) => c,
                    Err(_) => return Some("OK"),
                };
                let out_dir = handle
                    .path()
                    .app_data_dir()
                    .map(|d| d.join("received"))
                    .unwrap_or_else(|_| std::path::PathBuf::from("received"));
                let key = format!("{}:{}", from, offer_id);
                let done = {
                    let app_state = handle.state::<AppState>();
                    let mut inbox = app_state.file_inbox.lock().await;
                    crate::file_inbox::ingest_chunk(
                        &mut inbox,
                        &key,
                        idx as u32,
                        total as u32,
                        &chunk,
                        &out_dir,
                    )
                };
                if let Some(path) = done {
                    log::info!("File transfer {} from {} complete → {}", offer_id, from, path.display());
                    safe_emit(handle, "file-received", serde_json::json!({
                        "from": from,
                        "offer_id": offer_id,
                        "path": path.to_string_lossy(),
                    }));
                }
                Some("OK")
            } else {
                let offer_id = meta
                    .get("offer_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(id)
                    .to_string();
                let app_state = handle.state::<AppState>();
                let accepted = {
                    let mut inbox = app_state.file_inbox.lock().await;
                    crate::file_inbox::register_offer(&mut inbox, &format!("{}:{}", from, offer_id), name, *size)
                };
                if accepted {
                    safe_emit(handle, "file-offer", serde_json::json!({
                        "from": from,
                        "offer_id": &offer_id,
                        "name": name,
                        "size": size,
                    }));
                }
                Some("OK")
            }
        }
        // TI-2: unhandled types (file-transfer chunks, future variants) must
        // NOT fan out to `p2p-request` — the frontend treats that event as
        // "new contact request" and each 16 KiB chunk spawned a notification.
        _ => {
            log::debug!("Unhandled message type from {} — no UI event", from);
            Some("OK")
        }
    }
}
