use crate::p2p::{MessageType, NoidMessage};
use crate::AppState;
use tauri::State;

/// Invite a contact to an encrypted room — two-phase protocol.
///
/// Phase 1 (this command): send a `RoomInviteOffer` carrying ratchet-wrapped
/// room metadata (name/avatar/owner) but NO key. The invitee sees a pending
/// invite and must accept before anything else happens. Only then
/// (`RoomInviteAccept` → `deliver_room_key`) does the wrapped room key
/// travel — an unaccepted invite grants zero access to room traffic.
///
/// The invitee is recorded locally as a member with `is_approved=0` —
/// the row flips to approved when their `RoomInviteAccept` arrives.
#[tauri::command]
pub async fn invite_to_room(
    room_id: String,
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("room_id", &room_id, 64)?;
    crate::validation::parse_peer_id(&peer_id)?;
    // Room key + metadata must exist locally — we can only invite to
    // rooms we hold the key for, and only the recorded owner may invite
    // (membership is owner-managed). The offer carries name/avatar/owner
    // and the roster so the invitee's client can render the pending invite.
    let my_id = state.my_id.lock().await.clone();
    let (offer, already_member) = {
        let db_state = state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => {
                let key = db.get_room_key(&room_id).await.map_err(|e| e.to_string())?;
                let info = db.get_room_info(&room_id).await.map_err(|e| e.to_string())?;
                let members = db.get_room_members(&room_id).await.unwrap_or_default();
                let already = members
                    .iter()
                    .any(|m| m.peer_id == peer_id && m.approved);
                match (key, info) {
                    (Some(_), Some(info)) => {
                        if info.owner.as_deref() != Some(my_id.as_str()) {
                            return Err("Only the room owner can invite".to_string());
                        }
                        let roster = crate::room_control::room_roster(
                            db,
                            &room_id,
                            info.owner.as_deref(),
                            &my_id,
                        )
                        .await;
                        (
                            crate::p2p::RoomInviteOfferPayload {
                                name: Some(info.name),
                                avatar: info.avatar,
                                owner: info.owner,
                                epoch: info.key_epoch,
                                members: roster,
                            },
                            already,
                        )
                    }
                    _ => return Err("Unknown room or missing key".to_string()),
                }
            }
            None => return Err("Database not initialized".to_string()),
        }
    };
    if already_member {
        return Err("Peer is already a room member".to_string());
    }

    // Wrap the offer with the ratchet session — room metadata stays E2EE;
    // no session, no invite.
    let body = serde_json::to_vec(&offer).map_err(|e| e.to_string())?;
    let ratchet_msg = match state.ratchet_sessions.encrypt(&peer_id, &body).await {
        Ok(Some(m)) => m,
        _ => return Err("No E2EE session with this contact yet".to_string()),
    };

    // Persist the ratchet state advanced by the wrap, and record the
    // invitee as an UNAPPROVED member — they hold no key until they accept.
    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = state.ratchet_sessions.save_session(db, &peer_id).await;
            let _ = db.add_room_member(&room_id, &peer_id, false).await;
        }
    }

    let wrapped = serde_json::to_vec(&ratchet_msg).map_err(|e| e.to_string())?;
    let msg = NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RoomInviteOffer {
            room_id: room_id.clone(),
            wrapped_meta: wrapped,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: uuid::Uuid::new_v4().to_string(),
    };

    // F13: pending-first — a lost RoomInviteOffer wedges membership forever.
    crate::pend_typed_message(&state, &peer_id, &msg).await;

    crate::send_message_to_peer(&state, &peer_id, msg).await?;
    Ok(())
}
