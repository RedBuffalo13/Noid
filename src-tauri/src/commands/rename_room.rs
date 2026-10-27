use crate::p2p::{P2PCommand, RoomPayload};
use crate::AppState;
use tauri::State;

/// Owner-only room rename. Updates the local record and broadcasts the
/// new name in-topic (sealed envelope) — every member applies it.
#[tauri::command]
pub async fn rename_room(
    room_id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err("Invalid room name".to_string());
    }
    {
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
            return Err("Only the room owner can rename".to_string());
        }
        db.rename_room(&room_id, &name)
            .await
            .map_err(|e| e.to_string())?;
    }
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id,
                payload: RoomPayload::Meta {
                    name: Some(name),
                    avatar: None,
                },
            })
            .await;
    }
    Ok(())
}
