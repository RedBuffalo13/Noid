//! Peer presence + message-ack arms — extracted from the lib.rs event consumer (Q05/A5b).
//! Bodies moved verbatim.

use tauri::Manager;

use crate::p2p::P2PEvent;
use crate::{safe_emit, send_p2p_cmd, encode_pending_content, AppState};

pub(crate) async fn on_peer_event(
    event: P2PEvent,
    handle: &tauri::AppHandle,
    last_relay_status: &mut Option<crate::p2p::relay_status::RelayStatus>,
) {
    let handle = handle.clone();
    match event {
                            P2PEvent::PeerConnected(peer) => {
                                // A live connection IS the online fact — no
                                // Ping/Pong probes involved anymore.
                                safe_emit(&handle, "peer-connected", &peer);
                                safe_emit(&handle, "peer-online", &peer);
                                handle.state::<AppState>()
                                    .connected_peers.lock().await.insert(peer.clone());

                                let app_state = handle.state::<AppState>();

                                // Phase 0.3: Removed auto-send public key on PeerConnected.
                                // Keys are exchanged only on ContactRequest or when a key changes,
                                // preventing the PublicKeyExchange ping-pong that triggered deadlocks.

                                // Phase I.2: Trigger mailbox retrieval for self when a peer connects
                                // (messages may have been stored on a mailbox node while we were offline)
                                {
                                    if let Some(my_id) = app_state.current_peer_id().await {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                                peer_id: my_id,
                                            }).await;
                                        }
                                    }
                                }

                                // RC10: flush + rekey resend spawn off the
                                // forwarder — they walk the whole pending table
                                // and dial out; a connect storm would otherwise
                                // serialize the event loop for seconds.
                                // NOTE: the db guard MUST be dropped before resend_owned_keys()
                                // — that function locks app_state.db itself, and tokio's
                                // Mutex is not reentrant (this self-deadlock froze every
                                // DB-backed command after the first PeerConnected).
                                {
                                    let h = handle.clone();
                                    let peer_c = peer.clone();
                                    crate::track_task(&handle, tokio::spawn(async move {
                                        // RC2: snapshot Database (shared pool), release the
                                        // guard before my_id/security locks inside the loop.
                                        // F11: extracted into pending_flush — the
                                        // retry loop reuses this for connected peers.
                                        crate::pending_flush::flush_pending_for_peer(&h, &peer_c).await;

                                        // Reconnect self-heal: if this peer is a member of a
                                        // room we own, resend the current KeyUpdate — covers
                                        // rekeys that happened while they were offline.
                                        crate::room_rekey::resend_owned_keys(&h, &peer_c).await;
                                    })).await;
                                }
                            }
                            P2PEvent::PeerDisconnected(peer) => {
                                safe_emit(&handle, "peer-disconnected", &peer);
                                let app_state = handle.state::<AppState>();
                                app_state.connected_peers.lock().await.remove(&peer);
                                // F11: a contact we owe pending messages to gets a
                                // planned re-dial (ConnectToPeer resolves addrs via
                                // the DHT/cache; dial backoff inside the node bounds
                                // the churn). RC10: DB lookup off the forwarder.
                                let h = handle.clone();
                                crate::track_task(&handle, tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db = app_state.db.lock().await.clone();
                                    if let Some(db) = db {
                                        let has_pending = db
                                            .get_pending_messages(&peer)
                                            .await
                                            .map(|p| !p.is_empty())
                                            .unwrap_or(false);
                                        if has_pending {
                                            if let Some(tx) = app_state.p2p() {
                                                let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::ConnectToPeer {
                                                    peer_id: peer.clone(),
                                                    addr_hint: None,
                                                }).await;
                                            }
                                        }
                                    }
                                })).await;
                            }
                            P2PEvent::PeerOnline(peer) => {
                                safe_emit(&handle, "peer-online", &peer);
                            }
                            P2PEvent::MessageFailed { to, request_id: _, error, content, message_id, msg_type } => {
                                log::warn!("Message failed to send to {}: {}", to, error);

                                // Chat/RatchetChat get the plaintext pending/mailbox
                                // fallback. Typed messages (RoomControl, RoomInvite,
                                // ContactRequest, ContactAccept) carry a structured
                                // payload — they are re-pended as a serialized
                                // NoidMessage ("NOIDMSG1:") and resent verbatim on
                                // reconnect or via mailbox, so a contact request
                                // survives the recipient being offline.
                                let typed = matches!(
                                    msg_type,
                                    crate::p2p::MessageType::RoomControl { .. }
                                        | crate::p2p::MessageType::RoomChat { .. }
                                        | crate::p2p::MessageType::RoomInvite { .. }
                                        | crate::p2p::MessageType::RoomInviteOffer { .. }
                                        | crate::p2p::MessageType::RoomInviteAccept { .. }
                                        | crate::p2p::MessageType::RoomInviteDecline { .. }
                                        | crate::p2p::MessageType::ContactRequest { .. }
                                        | crate::p2p::MessageType::ContactAccept { .. }
                                        // A dropped X3DHInit leaves the peers
                                        // permanently desynced — it must retry
                                        // through pending/mailbox like the rest.
                                        | crate::p2p::MessageType::X3DHInit { .. }
                                        // Chat/RatchetChat ALSO serialize to
                                        // NOIDMSG1 — the wire msg_type carries
                                        // ciphertext+headers, enough to resend
                                        // verbatim. This kills the "no pending
                                        // row and no recoverable body" loss
                                        // class: a missing row is now rebuilt
                                        // instead of dropping the message.
                                        | crate::p2p::MessageType::Chat(_)
                                        | crate::p2p::MessageType::RatchetChat { .. }
                                );
                                if !typed {
                                    log::debug!("Skipping pending/mailbox fallback for non-chat message type");
                                    return;
                                }
                                // TI-3: emit only for user-visible chat failures
                                // (a dropped Ping/ReadReceipt must not mark the
                                // whole chat failed) and carry the message id so
                                // the frontend marks the single message.
                                safe_emit(&handle, "message-failed", serde_json::json!({
                                    "to": &to, "error": &error, "message_id": &message_id
                                }));

                                // RC10: re-pend + mailbox lookup spawn off the
                                // forwarder — DB writes and DHT lookups must not
                                // serialize other events.
                                let h = handle.clone();
                                let to = to.clone();
                                crate::track_task(&handle, tokio::spawn(async move {
                                let app_state = h.state::<AppState>();

                                // Re-pend the failed message under its ORIGINAL message_id —
                                // send_chat_message already stored it, so this mainly covers
                                // messages sent from other paths. The exists-check prevents
                                // duplicate pending rows (which would resend twice).
                                {
                                    // RC2: db snapshot — encode_pending_content
                                    // locks `security` internally; the global db
                                    // guard must not be held across it.
                                    let db = app_state.db.lock().await.clone();
                                    if let Some(db) = db {
                                        let already_pending = !message_id.is_empty()
                                            && db.pending_exists_by_message_id(&to, &message_id).await.unwrap_or(false);
                                        if already_pending {
                                            log::debug!("Message {} already in pending, not re-adding", message_id);
                                        } else if typed {
                                            let effective_id = if message_id.is_empty() {
                                                uuid::Uuid::new_v4().to_string()
                                            } else {
                                                message_id.clone()
                                            };
                                            let my_id = app_state.my_id.lock().await.clone();
                                            let reconstructed = crate::p2p::NoidMessage {
                                                sender: my_id,
                                                content: content.clone(),
                                                msg_type: msg_type.clone(),
                                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                id: effective_id.clone(),
                                            };
                                            match serde_json::to_string(&reconstructed) {
                                                Ok(json) => {
                                                    let body = format!("NOIDMSG1:{}", json);
                                                    match encode_pending_content(&app_state.security, &body).await {
                                                        Some(enc) => {
                                                            if let Err(e) = db.add_pending_message_with_content(&to, &enc, &effective_id).await {
                                                                log::error!("Failed to re-pend typed message {} for {}: {}", effective_id, to, e);
                                                            } else {
                                                                log::debug!("Typed message {} saved to pending_messages for {}", effective_id, to);
                                                            }
                                                        }
                                                        None => {
                                                            log::error!("Cannot persist failed message for {}: master key unavailable", to);
                                                        }
                                                    }
                                                }
                                                Err(e) => log::warn!("Cannot serialize typed message for pending: {}", e),
                                            }
                                        } else if content.is_empty() {
                                            // RatchetChat failures carry no plaintext (by design) —
                                            // without a pending row we cannot reconstruct the body.
                                            log::warn!("Failed message {} has no pending row and no recoverable body", message_id);
                                        } else {
                                            let effective_id = if message_id.is_empty() {
                                                uuid::Uuid::new_v4().to_string()
                                            } else {
                                                message_id.clone()
                                            };
                                            match encode_pending_content(&app_state.security, &content).await {
                                                Some(enc) => {
                                                    if let Err(e) = db.add_pending_message_with_content(&to, &enc, &effective_id).await {
                                                        log::error!("Failed to re-pend message {} for {}: {}", effective_id, to, e);
                                                    } else {
                                                        log::debug!("Message {} saved to pending_messages for {}", effective_id, to);
                                                    }
                                                }
                                                None => {
                                                    log::error!("Cannot persist failed message for {}: master key unavailable", to);
                                                }
                                            }
                                        }
                                    }
                                }

                                // Offline delivery goes through the recipient's mailbox node —
                                // the deprecated DHT message store is no longer written to.
                                if let Some(tx) = app_state.p2p() {
                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                        peer_id: to.clone(),
                                    }).await;
                                    log::debug!("Triggered mailbox lookup for {} after send failure", to);
                                }
                                })).await;
                            }
                            P2PEvent::MessageDelivered { peer_id, message_id } => {
                                // Phase 1.3: Delete pending message on confirmed delivery —
                                // scoped to (peer, id): a room fan-out ack must not
                                // remove another member's pending row.
                                // RC10: DB write off the forwarder path.
                                let h = handle.clone();
                                let (peer_id_c, message_id_c) = (peer_id.clone(), message_id.clone());
                                let task = tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db_state = app_state.db.lock().await;
                                    if let Some(db) = db_state.as_ref() {
                                        if let Err(e) = db.delete_pending_message_by_id(&peer_id_c, &message_id_c).await {
                                            log::warn!("Failed to delete pending {} after delivery: {}", message_id_c, e);
                                        } else {
                                            log::debug!("Deleted pending message {} after delivery confirmation", message_id_c);
                                        }
                                    }
                                });
                                crate::track_task(&handle, task).await;
                                safe_emit(&handle, "message-delivered", serde_json::json!({
                                    "peer_id": &peer_id,
                                    "message_id": &message_id,
                                    // Delivery-path annotation: this ack came
                                    // from direct request-response. Mailbox
                                    // deliveries clear the pending row through
                                    // MailboxStoreAck instead (queued path).
                                    "path": "direct",
                                }));
                            }
            ev => return crate::ev_dht::on_dht_event(ev, &handle, last_relay_status).await,
    }
}
