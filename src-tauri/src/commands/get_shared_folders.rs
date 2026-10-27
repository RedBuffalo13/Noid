use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_shared_folders(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, bool)>, String> {
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        db.get_shared_folders()
            .await
            .map_err(|e| e.to_string())
    } else {
        Err("Database not initialized".into())
    }
}
