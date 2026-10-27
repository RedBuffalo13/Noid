use crate::AppState;
use tauri::State;

/// (peer_id, nickname?, avatar?) rows.
type ContactRow = (String, Option<String>, Option<String>);

#[tauri::command]
pub async fn get_contacts(
    state: State<'_, AppState>,
) -> Result<Vec<ContactRow>, String> {
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        return db.get_contacts().await.map_err(|e| e.to_string());
    }
    Err("Database not initialized".into())
}
