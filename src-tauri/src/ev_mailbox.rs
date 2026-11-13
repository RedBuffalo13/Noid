//! Mailbox/security/relay-status arms — extracted from the lib.rs event consumer (Q05/A5b).
//! Bodies moved verbatim.

use tauri::Manager;

use crate::p2p::P2PEvent;
use crate::{safe_emit, send_p2p_cmd, decode_pending_content, AppState};

pub(crate) async fn on_mailbox_event(
    event: P2PEvent,
    handle: &tauri::AppHandle,
    last_relay_status: &mut Option<crate::p2p::relay_status::RelayStatus>,
) {
    let handle = handle.clone();
    match event {
                            P2PEvent::MailboxMessagesRetrieved { mailbox_peer_id, messages } => {
                                log::debug!("Retrieved {} messages from mailbox {}", messages.len(), mailbox_peer_id);
                                // Phase I.3: Process retrieved mailbox messages — decrypt, save to DB, emit, ack
                                let app_state = handle.state::<AppState>();
                                let db = app_state.db.clone();
                                let sessions = app_state.ratchet_sessions.clone();
                                let security = app_state.security.clone();
                                let dht_cipher = app_state.dht_cipher.lock()
                                    .map(|g| g.clone())
                                    .unwrap_or_else(|e| {
                                        log::error!("dht_cipher lock poisoned: {}", e);
                                        None
                                    });
                                let p2p_tx = app_state.p2p_tx.clone();
                                let handle_clone = handle.clone();
                                let decrypt_attempts = app_state.mailbox_decrypt_attempts.clone();
                                let mailbox_seen_hashes = app_state.mailbox_seen_hashes.clone();
                                let mailbox_peer_id_clone = mailbox_peer_id.clone();
                                let my_id = app_state.my_id.lock().await.clone();
                                crate::track_task(&handle, tokio::spawn(async move {
                                    // RC1: never hold the global db mutex across
                                    // dispatch calls — apply_room_control /
                                    // dispatch_contact_message / handle_x3dh_init
                                    // re-lock it through the AppHandle. Clone a
                                    // Database snapshot (shared pool + cipher) and
                                    // drop the guard immediately.
                                    let db = {
                                        let db_guard = db.lock().await;
                                        match db_guard.clone() {
                                            Some(d) => d,
                                            None => {
                                                log::error!("Mailbox processing: database not initialized");
                                                return;
                                            }
                                        }
                                    };
                                    let ctx = crate::process_mailbox_item::MailboxProcessCtx {
                                        handle: handle_clone,
                                        db,
                                        sessions,
                                        security,
                                        dht_cipher,
                                        p2p_tx,
                                        decrypt_attempts,
                                        seen_hashes: mailbox_seen_hashes,
                                        mailbox_peer_id: mailbox_peer_id_clone,
                                        my_id,
                                    };
                                    for item in messages {
                                        crate::process_mailbox_item::process_mailbox_item(&ctx, item).await;
                                    }
                                })).await;
                            }
                            P2PEvent::MailboxStoreAck { success, message_id, recipient_peer_id } => {
                                log::debug!("Mailbox store acknowledged: success={}", success);
                                if success {
                                    // The mailbox confirmed the store — only now
                                    // is the pending row safe to delete, scoped
                                    // to the actual recipient.
                                    if let Some(id) = message_id {
                                        let app_state = handle.state::<AppState>();
                                        let db_state = app_state.db.lock().await;
                                        if let Some(db) = db_state.as_ref() {
                                            if let Err(e) = db.delete_pending_message_by_id(&recipient_peer_id, &id).await {
                                                log::warn!("Failed to delete pending {} after mailbox store: {}", id, e);
                                            }
                                        }
                                        // DB27: emit only for Store-acks (id
                                        // present) — Delete-acks used to
                                        // produce phantom "stored" toasts.
                                        // TI-8/TI-4: carry ids so the UI can
                                        // mark THAT message as queued for
                                        // offline delivery (honest status —
                                        // stored ≠ peer-read).
                                        safe_emit(&handle, "mailbox-stored", serde_json::json!({
                                            "peer_id": &recipient_peer_id,
                                            "message_id": &id,
                                        }));
                                    }
                                } else {
                                    // Store failed or never reached the mailbox —
                                    // the pending row stays for the next retry.
                                    log::warn!("Mailbox store not confirmed (msg_id={:?}) — keeping pending", message_id);
                                }
                            }
                            P2PEvent::PendingUndeliverable { peer_id, message_id, reason } => {
                                // F12/F14: permanent failure — drop the pending
                                // row (scoped) and tell the UI the message is
                                // undeliverable instead of retrying forever.
                                log::warn!("Pending message to {} undeliverable: {}", peer_id, reason);
                                let app_state = handle.state::<AppState>();
                                let db_state = app_state.db.lock().await;
                                if let (Some(db), Some(id)) = (db_state.as_ref(), message_id.as_ref()) {
                                    if let Err(e) = db.delete_pending_message_by_id(&peer_id, id).await {
                                        log::warn!("Failed to delete undeliverable pending {}: {}", id, e);
                                    }
                                }
                                drop(db_state);
                                safe_emit(&handle, "message-failed", serde_json::json!({
                                    "to": peer_id,
                                    "error": reason,
                                }));
                            }
                            P2PEvent::MailboxError { error } => {
                                log::error!("Mailbox error: {}", error);
                            }
                            // D18: the mailbox resolver produced nothing —
                            // pending rows stay queued for the retry tick.
                            // No UI event needed; the log is the audit trail.
                            P2PEvent::MailboxNodeNotFound { peer_id } => {
                                log::debug!("No mailbox node resolved for peer {}", peer_id);
                            }
                            P2PEvent::MailboxNodeFound { peer_id, mailbox_peer_id, relay_addr, backup_mailbox_peer_id, backup_relay_addr } => {
                                log::debug!("Mailbox node found for {}: mailbox_peer={}, relay={}", peer_id, mailbox_peer_id, relay_addr);
                                let app_state = handle.state::<AppState>();
                                let my_id = app_state.my_id.lock().await.clone();

                                if mailbox_peer_id == my_id && peer_id != my_id {
                                    // MD-05: the peer's record resolves to OUR
                                    // node as the mailbox — storing locally
                                    // keeps delivery working instead of
                                    // silently dropping the envelopes.
                                    let db = app_state.db.lock().await.clone();
                                    let sessions = app_state.ratchet_sessions.clone();
                                    let security = app_state.security.clone();
                                    let dht_cipher = app_state.dht_cipher.lock()
                                        .map(|g| g.clone())
                                        .unwrap_or_else(|e| {
                                            log::error!("dht_cipher lock poisoned: {}", e);
                                            None
                                        });
                                    let my_id_clone = my_id.clone();
                                    let peer_id_clone = peer_id.clone();
                                    crate::track_task(&handle, tokio::spawn(async move {
                                        if let Some(db) = db {
                                            if let Ok(pending) = db.get_pending_messages(&peer_id_clone).await {
                                                for (_row_id, raw_content, msg_id) in pending {
                                                    let Some(content) = decode_pending_content(&security, &raw_content).await else {
                                                        continue;
                                                    };
                                                    // OPT-R05: shared encoders — RatchetChat
                                                    // serializes via serialize_ratchet_chat,
                                                    // ECDH fallback via encrypt_mailbox_ecdh.
                                                    let encrypted_content: Option<Vec<u8>> = if content.starts_with("NOIDMSG1:") {
                                                        serde_json::from_str::<crate::p2p::NoidMessage>(content.trim_start_matches("NOIDMSG1:"))
                                                            .ok()
                                                            .and_then(|m| crate::serialize_ratchet_chat::serialize_ratchet_chat(&m.msg_type))
                                                    } else {
                                                        match sessions.encrypt(&peer_id_clone, content.as_bytes()).await {
                                                            Ok(Some(rm)) => serde_json::to_vec(&rm).ok(),
                                                            _ => crate::encrypt_mailbox_ecdh::encrypt_mailbox_ecdh(
                                                                &db, dht_cipher.as_deref(), &peer_id_clone, &content,
                                                            ).await,
                                                        }
                                                    };
                                                    if let Some(enc) = encrypted_content {
                                                        let expires = (chrono::Utc::now() + chrono::Duration::days(7))
                                                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                                        if db.store_mailbox_message(
                                                            &msg_id, &peer_id_clone, &my_id_clone, &enc, &expires, &[],
                                                        ).await.is_ok() {
                                                            let _ = db.delete_pending_message_by_id(&peer_id_clone, &msg_id).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    })).await;
                                } else {
                                    // F1: seed the mailbox peer's addr from the
                                    // verified record — store/retrieve/ack used
                                    // to rely on the peer cache alone and
                                    // stalled forever on unknown mailboxes.
                                    if !mailbox_peer_id.is_empty() && !relay_addr.is_empty() {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SeedPeerAddr {
                                                peer_id: mailbox_peer_id.clone(),
                                                addr: relay_addr.clone(),
                                            }).await;
                                        }
                                    }
                                }
                                if mailbox_peer_id == my_id {
                                    // handled above
                                } else if peer_id == my_id {
                                    // Phase I: This is OUR mailbox — retrieve stored messages
                                    if !mailbox_peer_id.is_empty() {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::RetrieveFromMailbox {
                                                mailbox_peer_id: mailbox_peer_id.clone(),
                                                recipient_peer_id: my_id.clone(),
                                            }).await;
                                            // META-02: also poll the blind box —
                                            // today and yesterday at the rotation
                                            // boundary, in one ephemeral session.
                                            let day = crate::p2p::blind_box::current_day();
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::RetrieveFromMailboxBlind {
                                                mailbox_peer_id: mailbox_peer_id.clone(),
                                                days: vec![day, day - 1],
                                            }).await;
                                            log::debug!("Requested mailbox retrieval from {} for self", mailbox_peer_id);
                                        }
                                    }
                                } else {
                                    // This is someone else's mailbox — send our pending messages to it.
                                    if mailbox_peer_id.is_empty() {
                                        log::warn!("Mailbox node found for {} but no mailbox_peer_id — cannot send", peer_id);
                                        return;
                                    }
                                    let db = app_state.db.clone();
                                    let sessions = app_state.ratchet_sessions.clone();
                                    let p2p_tx = app_state.p2p_tx.clone();
                                    let security = app_state.security.clone();
                                    let dht_cipher = app_state.dht_cipher.lock()
                                        .map(|g| g.clone())
                                        .unwrap_or_else(|e| {
                                            log::error!("dht_cipher lock poisoned: {}", e);
                                            None
                                        });
                                    let my_id_clone = my_id.clone();
                                    let mailbox_peer_id_clone = mailbox_peer_id.clone();
                                    let peer_id_clone = peer_id.clone();
                                    let backup_mb_clone = backup_mailbox_peer_id.clone();
                                    let _backup_addr_clone = backup_relay_addr.clone();
                                    crate::track_task(&handle, tokio::spawn(async move {
                                        // RC2: snapshot Database — decode_pending_content
                                        // locks `security` inside the loop.
                                        let db = db.lock().await.clone();
                                        if let Some(db) = db {
                                            if let Ok(pending) = db.get_pending_messages(&peer_id_clone).await {
                                                // get_pending_messages returns (id, content, message_id).
                                                for (_row_id, raw_content, msg_id) in pending {
                                                    let Some(content) = decode_pending_content(&security, &raw_content).await else {
                                                        log::warn!("Skipping undecryptable pending row for mailbox {}", peer_id_clone);
                                                        continue;
                                                    };
                                                    // MD-01: NOIDMSG1: payloads carry their own
                                                    // wire format — a RatchetChat row is already a
                                                    // serialized RatchetMessage (re-encrypting it
                                                    // advances the chain for nothing), and an
                                                    // X3DHInit must NEVER ride the session it
                                                    // bootstraps (chicken-and-egg: the receiver
                                                    // cannot decrypt the init that creates the
                                                    // session). Typed payloads go through the
                                                    // ECDH envelope; plain content uses ratchet
                                                    // when a session exists.
                                                    // OPT-R05: shared encoders — caller policy
                                                    // (typed payloads ride ECDH only here;
                                                    // self-path refuses non-RatchetChat) stays.
                                                    let encrypted_content: Option<Vec<u8>> = if let Some(json) = content.strip_prefix("NOIDMSG1:") {
                                                        match serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                                                            Ok(m) => match crate::serialize_ratchet_chat::serialize_ratchet_chat(&m.msg_type) {
                                                                Some(b) => Some(b),
                                                                None => match crate::encrypt_mailbox_ecdh::encrypt_mailbox_ecdh(
                                                                    &db, dht_cipher.as_deref(), &peer_id_clone, &content,
                                                                ).await {
                                                                    Some(b) => Some(b),
                                                                    None => {
                                                                        log::warn!("No DHT key for typed mailbox payload to {} — keeping pending", peer_id_clone);
                                                                        None
                                                                    }
                                                                },
                                                            },
                                                            Err(_) => {
                                                                log::warn!("Corrupt NOIDMSG1 pending row for {} — keeping", peer_id_clone);
                                                                None
                                                            }
                                                        }
                                                    } else {
                                                        match sessions.encrypt(&peer_id_clone, content.as_bytes()).await {
                                                            Ok(Some(ratchet_msg)) => serde_json::to_vec(&ratchet_msg).ok(),
                                                            _ => match crate::encrypt_mailbox_ecdh::encrypt_mailbox_ecdh(
                                                                &db, dht_cipher.as_deref(), &peer_id_clone, &content,
                                                            ).await {
                                                                Some(b) => Some(b),
                                                                None => {
                                                                    log::warn!("No ratchet session or DHT key for {} — keeping pending", peer_id_clone);
                                                                    None
                                                                }
                                                            },
                                                        }
                                                    };
                                                    let Some(encrypted_content) = encrypted_content else {
                                                        log::warn!("Envelope encryption failed for {} — not sending to mailbox", peer_id_clone);
                                                        continue;
                                                    };
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        // The pending row is NOT deleted here — only a real
                                                        // MailboxStoreAck confirms the store. Deleting on
                                                        // channel-send used to lose messages whenever the
                                                        // dial to the mailbox node failed.
                                                        // META-02: prefer sealed-sender blind delivery when
                                                        // the recipient's X3DH identity key is known — the
                                                        // mailbox then sees neither sender nor content.
                                                        let mut sent_blind = false;
                                                        let recipient_idpub = db
                                                            .get_contact_public_key(&peer_id_clone)
                                                            .await
                                                            .ok()
                                                            .flatten();
                                                        if let Some(idpub) = recipient_idpub {
                                                            if let Some(sealed) = crate::security::sealed_sender::seal(
                                                                &idpub,
                                                                &my_id_clone,
                                                                &msg_id,
                                                                &encrypted_content,
                                                            ) {
                                                                if let Ok(ed_pub) = crate::security::identity_sig::pubkey_from_peer_id(&peer_id_clone)
                                                                    .and_then(|k| k.try_into_ed25519().map(|e| e.to_bytes().to_vec()).map_err(|_| anyhow::anyhow!("not ed25519")))
                                                                {
                                                                    let day = crate::p2p::blind_box::current_day();
                                                                    let box_id = crate::p2p::blind_box::blind_box_id(&ed_pub, day);
                                                                    let sealed_c = sealed.clone();
                                                                    let box_c = box_id.clone();
                                                                    let nonce = tokio::task::spawn_blocking(move || {
                                                                        crate::p2p::blind_box::solve_pow(&box_c, &sealed_c)
                                                                    }).await.unwrap_or(0);
                                                                    for mbx in std::iter::once(&mailbox_peer_id_clone)
                                                                        .chain(backup_mb_clone.iter())
                                                                    {
                                                                        let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendToMailboxBlind {
                                                                            mailbox_peer_id: mbx.clone(),
                                                                            box_id: box_id.clone(),
                                                                            sealed: sealed.clone(),
                                                                            pow_nonce: nonce,
                                                                            client_msg_id: Some(msg_id.clone()),
                                                                            recipient_peer_id: peer_id_clone.clone(),
                                                                        }).await;
                                                                    }
                                                                    sent_blind = true;
                                                                }
                                                            }
                                                        }
                                                        if !sent_blind {
                                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendToMailbox {
                                                                mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                                recipient_peer_id: peer_id_clone.clone(),
                                                                sender_peer_id: my_id_clone.clone(),
                                                                encrypted_content,
                                                                client_msg_id: Some(msg_id),
                                                            }).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    })).await;
                                }
                            }
                            P2PEvent::SecurityAlert { code, detail } => {
                                // SEC-1111-02: pinned-trust failures must be
                                // audible — write to the durable audit log
                                // and surface a one-shot UI warning.
                                log::error!("Security alert {}: {}", code, detail);
                                let app_state = handle.state::<AppState>();
                                let _ = app_state
                                    .audit_log
                                    .log("security_alert", &format!("{}: {}", code, detail));
                                safe_emit(&handle, "security-alert", serde_json::json!({
                                    "code": code,
                                    "detail": detail,
                                }));
                            }
                            P2PEvent::RelayStatusChanged { status } => {
                                if last_relay_status.as_ref() == Some(&status) {
                                    return;
                                }
                                log::info!(
                                    "relay-status → UI: peers={} relays={} reservations={} addrs={:?}",
                                    status.peers_connected,
                                    status.known_relays,
                                    status.active_reservations,
                                    status.relayed_addrs
                                );
                                let app_state = handle.state::<AppState>();
                                *app_state.relay_status.lock().await = status.clone();
                                safe_emit(&handle, "relay-status", status.clone());
                                *last_relay_status = Some(status);
                            }
            _ => {}
    }
}
