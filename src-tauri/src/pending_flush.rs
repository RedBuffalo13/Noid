//! F11: pending-message flush for a peer with a live connection.
//! Extracted from the PeerConnected arm so the periodic retry loop can
//! reuse the same direct-delivery path instead of waiting for the
//! mailbox cycle.

use tauri::Manager;

use crate::{decode_pending_content, safe_emit, send_p2p_cmd, AppState};

/// Resend every pending row for `peer` over the live connection.
/// Rows stay in pending until `MessageDelivered` confirms durable
/// processing on the remote side.
pub(crate) async fn flush_pending_for_peer(handle: &tauri::AppHandle, peer: &str) {
    let app_state = handle.state::<AppState>();
    // MD-08: 10s per-peer cooldown — a PeerConnected flush and the retry
    // tick used to double-fire a full resend seconds apart; each ratchet
    // message in the burst advanced send_n for nothing.
    {
        let mut cd = app_state.pending_flush_cooldown.lock().await;
        let now = std::time::Instant::now();
        if cd
            .get(peer)
            .map(|t| now.duration_since(*t) < std::time::Duration::from_secs(10))
            .unwrap_or(false)
        {
            return;
        }
        cd.insert(peer.to_string(), now);
    }
    // RC2: db snapshot — decode_pending_content locks `security` inside
    // the loop; the global db guard must not be held across it.
    let db = app_state.db.lock().await.clone();
    let Some(db) = db else { return };
    let Ok(pending) = db.get_pending_messages(peer).await else { return };
    if pending.is_empty() {
        return;
    }
    let my_id = app_state.my_id.lock().await.clone();
    let sessions = app_state.ratchet_sessions.clone();
    let security = app_state.security.clone();
    let Some(tx) = app_state.p2p() else { return };

    // One X3DH fetch per peer per flush — N pending messages used to
    // fire N identical DHT lookups.
    let mut prekey_requested = false;
    // F15: a pending X3DHInit is already in flight — a fresh
    // FetchPrekeyBundle would race it and desync the new session.
    let mut init_in_flight = false;
    for (id, raw_content, message_id) in pending {
        let Some(content) = decode_pending_content(&security, &raw_content).await else {
            log::warn!("Skipping undecryptable pending row {}", id);
            continue;
        };
        // Typed messages (RoomControl, RoomInvite, …) were stored as
        // serialized NoidMessage — resend as-is; the inner payload is
        // already ratchet-wrapped.
        if let Some(json) = content.strip_prefix("NOIDMSG1:") {
            if let Ok(msg) = serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                if matches!(msg.msg_type, crate::p2p::MessageType::X3DHInit { .. }) {
                    init_in_flight = true;
                }
                let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage {
                    peer_id: peer.to_string(),
                    msg,
                })
                .await;
            }
            continue;
        }
        // Try to load session from DB if not in memory.
        if !sessions.has_session(peer).await {
            let _ = sessions.load_session(&db, peer).await;
        }
        match sessions.encrypt(peer, content.as_bytes()).await {
            Ok(Some(ratchet_msg)) => {
                let msg = crate::p2p::NoidMessage {
                    sender: my_id.clone(),
                    content: String::new(),
                    msg_type: crate::p2p::MessageType::RatchetChat {
                        ciphertext: ratchet_msg.ciphertext,
                        header_dh_public: ratchet_msg.header.dh_public,
                        header_pn: ratchet_msg.header.pn,
                        header_n: ratchet_msg.header.n,
                    },
                    timestamp: Some(chrono::Utc::now().to_rfc3339_opts(
                        chrono::SecondsFormat::Millis,
                        true,
                    )),
                    id: message_id,
                };
                if send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage {
                    peer_id: peer.to_string(),
                    msg,
                })
                .await
                .is_ok()
                {
                    safe_emit(handle, "pending-messages-sent", peer);
                    // Row stays until MessageDelivered; save_session still
                    // needed — encryption consumed ratchet state.
                    let _ = sessions.save_session(&db, peer).await;
                } else {
                    log::warn!("Failed to send pending message to {}", peer);
                }
            }
            _ => {
                // No session — initiate X3DH handshake, keep in pending.
                // F15: skip if an init is already queued for this flush.
                if !prekey_requested && !init_in_flight {
                    prekey_requested = true;
                    log::debug!(
                        "No ratchet session for {}, initiating X3DH handshake for pending message",
                        peer
                    );
                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FetchPrekeyBundle {
                        peer_id: peer.to_string(),
                    })
                    .await;
                }
            }
        }
    }
}
