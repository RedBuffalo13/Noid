use crate::AppState;
use tauri::State;

/// FE-A08: persist a peer's unread count — survives restarts so a message
/// never becomes silently "read" by process restart.
#[tauri::command]
pub async fn set_unread_count(
    peer_id: String,
    count: i64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    if !(0..=1_000_000).contains(&count) {
        return Err("unread count out of range".to_string());
    }
    let db = state.require_db().await?;
    db.set_unread_count(&peer_id, count)
        .await
        .map_err(|e| e.to_string())
}
