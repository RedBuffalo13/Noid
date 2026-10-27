use crate::p2p::{MessageType, P2PCommand, NoidMessage};
use crate::AppState;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn send_contact_request(
    peer_id: String,
    message: String,
    addr_hints: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if peer_id.parse::<libp2p::PeerId>().is_err() {
        return Err("Invalid Peer ID format".into());
    }

    {
        if let Some(tx) = state.p2p() {
            // Dial each address hint first — this is the cold-start path for
            // a node with an empty DHT (invite link carries reachable addrs).
            for addr in addr_hints.unwrap_or_default() {
                let _ = crate::send_p2p_cmd(&tx, P2PCommand::ConnectToPeer {
                        peer_id: peer_id.clone(),
                        addr_hint: Some(addr),
                    })
                    .await;
            }
            // Always also queue a DHT lookup — covers stale/missing hints.
            crate::send_p2p_cmd(&tx, P2PCommand::ConnectToPeer {
                peer_id: peer_id.clone(),
                addr_hint: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        } else {
            return Err("P2P not initialized".to_string());
        }
    }

    // Phase 0.5: Removed sleep(3s). libp2p queues the message until connected.

    let (nickname, avatar) = {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            if let Ok(profile) = db.get_profile().await {
                (profile.0, profile.1)
            } else {
                ("NoidUser".to_string(), None)
            }
        } else {
            ("NoidUser".to_string(), None)
        }
    };

    let my_id = state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: message.clone(),
        msg_type: MessageType::ContactRequest {
            message,
            nickname,
            avatar,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: Uuid::new_v4().to_string(),
    };

    // F13: pending-first — the row must exist before the send is queued, so a
    // crash between enqueue and OutboundFailure cannot lose the request.
    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            if let Some(enc) = crate::encode_pending_content(&state.security, &format!("NOIDMSG1:{}", serde_json::to_string(&msg).unwrap_or_default())).await {
                if let Err(e) = db
                    .add_pending_message_with_content(&peer_id, &enc, &msg.id)
                    .await
                {
                    // RC21: a failed pend means the request won't survive an
                    // offline recipient — surface it in the log.
                    log::error!("Failed to pend contact request {} for {}: {}", msg.id, peer_id, e);
                }
            } else {
                log::error!("Cannot pend contact request for {}: master key unavailable", peer_id);
            }
        }
    }

    if let Some(tx) = state.p2p() {
        crate::send_p2p_cmd(&tx, P2PCommand::SendMessage { peer_id: peer_id.clone(), msg })
            .await
            .map_err(|e| e.to_string())?;

        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendPublicKey { peer_id: peer_id.clone() }).await;
    }

    // S16: remember that we asked — an inbound ContactAccept is only legit
    // as a reply to this marker (unsolicited accepts get parked as requests).
    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            if let Err(e) = db.add_outgoing_contact_request(&peer_id).await {
                // RC21/S16: without the marker a legit ContactAccept gets
                // parked — loud failure, not silent.
                log::error!("Failed to record outgoing contact request for {}: {}", peer_id, e);
            }
        }
    }
    Ok(())
}
