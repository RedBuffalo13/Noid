use crate::p2p::{P2PCommand, RoomPayload};
use crate::AppState;
use tauri::State;

/// Owner-only room avatar update. `avatar` is a data-URL (or None to
/// clear); the size bound matches profile avatars (256 KiB base64).
#[tauri::command]
pub async fn set_room_avatar(
    room_id: String,
    avatar: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if let Some(a) = &avatar {
        if a.len() > 256 * 1024 {
            return Err("Avatar too large".to_string());
        }
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
            return Err("Only the room owner can change the avatar".to_string());
        }
        db.set_room_avatar(&room_id, avatar.as_deref())
            .await
            .map_err(|e| e.to_string())?;
    }
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id,
                payload: RoomPayload::Meta {
                    name: None,
                    avatar,
                },
            })
            .await;
    }
    Ok(())
}
