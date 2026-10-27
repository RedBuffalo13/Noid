use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn update_last_sync_time(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let db = state.require_db().await?;
    let current_time =
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    db.set_last_sync_time(&current_time)
        .await
        .map_err(|e| e.to_string())
}
