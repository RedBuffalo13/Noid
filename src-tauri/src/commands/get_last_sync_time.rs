use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_last_sync_time(
    state: State<'_, AppState>,
) -> Result<String, String> {
    // RC18: SQL lives in db/profile_store.rs — commands are thin adapters.
    let db = state.require_db().await?;
    db.get_last_sync_time().await.map_err(|e| e.to_string())
}
