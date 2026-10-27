use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_username(
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        db.get_username().await.map_err(|e| e.to_string())
    } else {
        Err("Database not initialized".into())
    }
}
