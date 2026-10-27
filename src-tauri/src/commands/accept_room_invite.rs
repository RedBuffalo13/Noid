use crate::p2p::{MessageType, NoidMessage};
use crate::AppState;
use tauri::State;

/// Accept a pending room invite: notify the inviter with
/// `RoomInviteAccept` — they then deliver the ratchet-wrapped room key
/// (`RoomInvite`), which materializes the room locally. The pending row
/// is deliberately KEPT until the key actually arrives
/// (`apply_room_invite` deletes it): if the accept or the key delivery
/// is lost, the invite stays retryable instead of vanishing.
#[tauri::command]
pub async fn accept_room_invite(
    room_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("room_id", &room_id, 64)?;
    let inviter = {
        let db_state = state.db.lock().await;
        let db = db_state.as_ref().ok_or("Database not initialized")?;
        db.get_pending_room_invite_inviter(&room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("No pending invite for this room")?
    };

    let my_id = state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RoomInviteAccept {
            room_id: room_id.clone(),
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: uuid::Uuid::new_v4().to_string(),
    };
    crate::pend_typed_message(&state, &inviter, &msg).await;
    crate::send_message_to_peer(&state, &inviter, msg).await?;
    Ok(())
}
