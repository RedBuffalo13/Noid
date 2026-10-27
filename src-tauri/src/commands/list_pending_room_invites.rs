use crate::AppState;
use tauri::State;

/// Pending room invites awaiting user consent:
/// `(room_id, inviter_peer_id, name, avatar)` — the room name/avatar come
/// from the inviter's offer so the UI can render a recognizable request.
type PendingRoomInvite = (String, String, Option<String>, Option<String>);

#[tauri::command]
pub async fn list_pending_room_invites(
    state: State<'_, AppState>,
) -> Result<Vec<PendingRoomInvite>, String> {
    let db_state = state.db.lock().await;
    let db = db_state.as_ref().ok_or("Database not initialized")?;
    db.get_pending_room_invites()
        .await
        .map_err(|e| e.to_string())
}
