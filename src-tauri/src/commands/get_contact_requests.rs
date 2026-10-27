use crate::AppState;
use tauri::State;

/// (sender, message, timestamp, nickname?) rows.
type ContactRequestRow = (String, String, String, Option<String>);

#[tauri::command]
pub async fn get_contact_requests(
    state: State<'_, AppState>,
) -> Result<Vec<ContactRequestRow>, String> {
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        return db.get_contact_requests().await.map_err(|e| e.to_string());
    }
    Err("Database not initialized".into())
}
