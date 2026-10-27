use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_profile(state: State<'_, AppState>) -> Result<(String, Option<String>), String> {
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        return db.get_profile().await.map_err(|e| e.to_string());
    }
    Err("Database not initialized".into())
}
