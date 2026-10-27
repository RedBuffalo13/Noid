use crate::p2p::{MessageType, NoidMessage};
use crate::AppState;
use tauri::State;

/// Decline a pending room invite: notify the inviter with
/// `RoomInviteDecline` (they drop the pending member row — no key is ever
/// delivered) and remove the local pending invite.
#[tauri::command]
pub async fn decline_room_invite(
    room_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("room_id", &room_id, 64)?;
    let inviter = {
        let db_state = state.db.lock().await;
        let db = db_state.as_ref().ok_or("Database not initialized")?;
        let inviter = db
            .get_pending_room_invite_inviter(&room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("No pending invite for this room")?;
        db.delete_pending_room_invite(&room_id)
            .await
            .map_err(|e| e.to_string())?;
        inviter
    };

    let my_id = state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RoomInviteDecline {
            room_id: room_id.clone(),
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: uuid::Uuid::new_v4().to_string(),
    };
    crate::pend_typed_message(&state, &inviter, &msg).await;
    if let Err(e) = crate::send_message_to_peer(&state, &inviter, msg).await {
        // Offline decline stays pending — log, don't fail the UX.
        log::debug!("Decline send deferred for {}: {}", inviter, e);
    }
    Ok(())
}
