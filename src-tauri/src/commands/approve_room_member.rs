use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn approve_room_member(
    room_id: String,
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("room_id", &room_id, 64)?;
    crate::validation::parse_peer_id(&peer_id)?;
    // S9: approval is a room mutation — only the owner may flip is_approved
    // (every neighbouring mutation already enforces this).
    let my_id = state.my_id.lock().await.clone();
    let db = state.require_db().await?;
    let info = db
        .get_room_info(&room_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Unknown room")?;
    if info.owner.as_deref() != Some(my_id.as_str()) {
        return Err("Only the room owner can approve members".to_string());
    }
    db.approve_member(&room_id, &peer_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
