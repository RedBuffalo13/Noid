//! Username/prekey DHT arms — extracted from the lib.rs event consumer (Q05/A5b).
//! Bodies moved verbatim.

use tauri::Manager;

use crate::p2p::P2PEvent;
use crate::{safe_emit, send_p2p_cmd, p2p_sender, decode_pending_content, encode_pending_content, AppState};

pub(crate) async fn on_dht_event(
    event: P2PEvent,
    handle: &tauri::AppHandle,
    last_relay_status: &mut Option<crate::p2p::relay_status::RelayStatus>,
) {
    let handle = handle.clone();
    match event {
                            P2PEvent::UsernameAvailabilityChecked { username, available, uncertain } => {
                                safe_emit(&handle, "username-availability", serde_json::json!({
                                    "username": &username,
                                    "available": available,
                                    "uncertain": uncertain,
                                }));
                            }
                            P2PEvent::UserLookupResult { username, record } => {
                                if let Some(ref rec) = record {
                                    log::debug!("User lookup result: found user '{}' with peer_id {}", username, rec.peer_id);
                                } else {
                                    log::debug!("User lookup result: no user found for '{}'", username);
                                }
                                safe_emit(&handle, "user-lookup-result", serde_json::json!({
                                    "username": &username,
                                    "record": record,
                                }));
                            }
                            P2PEvent::PrekeyBundleRetrieved { peer_id, bundle } => {
                                match bundle {
                                    Some(b) => {
                                        log::debug!("Prekey bundle retrieved for peer {}", peer_id);
                                        // Phase A.4: Initiate X3DH session with the retrieved bundle
                                        let app_state = handle.state::<AppState>();
                                        let sessions = app_state.ratchet_sessions.clone();
                                        let db = app_state.db.clone();
                                        let p2p_tx = app_state.p2p_tx.clone();
                                        let audit_log = app_state.audit_log.clone();
                                        let security_arc = app_state.security.clone();
                                        let my_id_for_retry = app_state.my_id.lock().await.clone();
                                        let peer_id_owned = peer_id.clone();
                                        let track_h = handle.clone();
                                        crate::track_task(&handle, tokio::spawn(async move {
                                            match sessions.initiate_session(&peer_id_owned, &b).await {
                                                Ok(initial_msg) => {
                                                    log::info!("X3DH session initiated with {}", peer_id_owned);
                                                    // Phase E: Log key exchange
                                                    let _ = audit_log.log_key_exchange(&peer_id_owned);
                                                    // MD-01: persist the peer's X25519 identity
                                                    // from the signed bundle — the mailbox
                                                    // envelope path needs it for
                                                    // encrypt_for_recipient before any
                                                    // direct PublicKeyExchange happened.
                                                    let session_db = match crate::persist_initiated_session::persist_initiated_session(
                                                        &db, &sessions, &peer_id_owned, &b.identity_public,
                                                    ).await {
                                                        Ok(db) => db,
                                                        Err(e) => {
                                                            log::error!("Failed to persist initiated session for {}: {}", peer_id_owned, e);
                                                            return;
                                                        }
                                                    };
                                                    log::info!("X3DH session persisted for {}", peer_id_owned);
                                                    // Send X3DHInit message to peer
                                                    let noid_msg = crate::p2p::types::NoidMessage {
                                                        id: uuid::Uuid::new_v4().to_string(),
                                                        msg_type: crate::p2p::types::MessageType::X3DHInit {
                                                            identity_public: initial_msg.identity_public.clone(),
                                                            ephemeral_public: initial_msg.ephemeral_public.clone(),
                                                            one_time_prekey_id: initial_msg.one_time_prekey_id.clone(),
                                                            // S21: signed by the node at send time.
                                                            identity_signature: Vec::new(),
                                                        },
                                                        sender: String::new(),
                                                        content: String::new(),
                                                        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                    };
                                                    // F13/F15: pend the X3DHInit BEFORE queueing — a dropped
                                                    // init leaves peers desynced, and the crash window between
                                                    // enqueue and OutboundFailure must not lose it.
                                                    {
                                                        if let Ok(json) = serde_json::to_string(&noid_msg) {
                                                            if let Some(enc) = encode_pending_content(&security_arc, &format!("NOIDMSG1:{}", json)).await {
                                                                if let Err(e) = session_db.add_pending_message_with_content(&peer_id_owned, &enc, &noid_msg.id).await {
                                                                    log::error!("Failed to pend X3DHInit {} for {}: {}", noid_msg.id, peer_id_owned, e);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        if let Err(e) = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                            peer_id: peer_id_owned.clone(),
                                                            msg: noid_msg,
                                                        }).await {
                                                            log::error!("Failed to send X3DHInit: {}", e);
                                                        }
                                                    }
                                                    // Phase G.2: Auto-retry pending messages now that session is established.
                                                    // Wait 1s for X3DHInit to be delivered, then encrypt + send queued messages.
                                                    let db_for_retry = db.clone();
                                                    let sessions_for_retry = sessions.clone();
                                                    let p2p_tx_for_retry = p2p_tx.clone();
                                                    let security_for_retry = security_arc.clone();
                                                    let my_id_for_retry2 = my_id_for_retry.clone();
                                                    let peer_id_for_retry = peer_id_owned.clone();
                                                    crate::track_task(&track_h, tokio::spawn(async move {
                                                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                                        // RC2: snapshot Database —
                                                        // decode_pending_content locks
                                                        // `security`, the global db
                                                        // guard must not be held here.
                                                        let db = db_for_retry.lock().await.clone();
                                                        if let Some(db) = db {
                                                            if let Ok(pending) = db.get_pending_messages(&peer_id_for_retry).await {
                                                                for (id, raw_content, message_id) in pending {
                                                                    let Some(content) = decode_pending_content(&security_for_retry, &raw_content).await else {
                                                                        log::warn!("Pending row {} undecryptable — skipped", id);
                                                                        continue;
                                                                    };
                                                                    if let Some(json) = content.strip_prefix("NOIDMSG1:") {
                                                                        if let Ok(msg) = serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                                                                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                                                                // send() only enqueues — the row
                                                                                // is deleted on MessageDelivered.
                                                                                let _ = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                                                    peer_id: peer_id_for_retry.clone(),
                                                                                    msg,
                                                                                }).await;
                                                                            }
                                                                        }
                                                                        continue;
                                                                    }
                                                                    match sessions_for_retry.encrypt(&peer_id_for_retry, content.as_bytes()).await {
                                                                        Ok(Some(ratchet_msg)) => {
                                                                            let noid_msg = crate::p2p::types::NoidMessage {
                                                                                id: message_id.clone(),
                                                                                sender: my_id_for_retry2.clone(),
                                                                                content: String::new(),
                                                                                msg_type: crate::p2p::types::MessageType::RatchetChat {
                                                                                    ciphertext: ratchet_msg.ciphertext,
                                                                                    header_dh_public: ratchet_msg.header.dh_public,
                                                                                    header_pn: ratchet_msg.header.pn,
                                                                                    header_n: ratchet_msg.header.n,
                                                                                },
                                                                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                                            };
                                                                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                                                                let _ = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                                                    peer_id: peer_id_for_retry.clone(),
                                                                                    msg: noid_msg,
                                                                                }).await;
                                                                            }
                                                                            // Row stays until MessageDelivered.
                                                                        }
                                                                        _ => log::warn!("Failed to encrypt pending message {}", message_id),
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })).await;
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to initiate X3DH session with {}: {}", peer_id_owned, e);
                                                }
                                            }
                                        })).await;
                                    }
                                    None => {
                                        log::warn!("No prekey bundle found for peer {}", peer_id);
                                        safe_emit(&handle, "message-failed", serde_json::json!({
                                            "to": &peer_id,
                                            "error": "No prekey bundle found — cannot establish E2EE session",
                                        }));
                                    }
                                }
                            }
            ev => return crate::ev_mailbox::on_mailbox_event(ev, &handle, last_relay_status).await,
    }
}
