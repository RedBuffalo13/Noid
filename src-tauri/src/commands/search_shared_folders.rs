use crate::AppState;
use tauri::State;

/// (path, name?, is_mine, owner?) rows.
type SharedFolderRow = (String, String, bool, Option<String>);

#[tauri::command]
pub async fn search_shared_folders(
    query: String,
    state: State<'_, AppState>,
) -> Result<Vec<SharedFolderRow>, String> {
    if query.len() > 256 {
        return Err("Query too long (max 256 characters)".into());
    }

    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        db.search_shared_folders(&query)
            .await
            .map_err(|e| e.to_string())
    } else {
        Err("Database not initialized".into())
    }
}
