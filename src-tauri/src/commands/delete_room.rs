use crate::p2p::{P2PCommand, RoomControlPayload};
use crate::room_control::send_room_control;
use crate::AppState;
use tauri::State;

/// Owner-only room deletion: notifies every member via ratchet-encrypted
/// `Deleted` control messages, then wipes the room locally and
/// unsubscribes. Members delete their copy on receipt.
#[tauri::command]
pub async fn delete_room(
    app: tauri::AppHandle,
    room_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let members = {
        let my_id = state.my_id.lock().await.clone();
        let db_state = state.db.lock().await;
        let Some(db) = db_state.as_ref() else {
            return Err("Database not initialized".to_string());
        };
        let info = db
            .get_room_info(&room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Unknown room")?;
        if info.owner.as_deref() != Some(my_id.as_str()) {
            return Err("Only the room owner can delete the room".to_string());
        }
        db.get_room_members(&room_id)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| m.peer_id)
            .collect::<Vec<_>>()
    };

    for peer in members {
        let _ = send_room_control(&app, &room_id, &peer, &RoomControlPayload::Deleted).await;
    }

    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            // RC21: the delete is the command's core action — failure must
            // surface, not silently Ok while the room stays in the list.
            db.delete_room(&room_id).await.map_err(|e| e.to_string())?;
        }
    }
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::LeaveRoom { room_id }).await;
    }
    Ok(())
}
