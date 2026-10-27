use crate::AppState;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn register_folder(path: String, state: State<'_, AppState>) -> Result<(), String> {
    // Never trust the frontend — mirror update_folder_path validation:
    // unbounded or traversal paths would become a sink for any future
    // consumer of the shared-folders table.
    if path.len() > 1024 {
        return Err("Path too long (max 1024 characters)".into());
    }
    if path.contains("..") {
        return Err("Path traversal is not allowed".into());
    }
    let db = state.require_db().await?;
    let id = Uuid::new_v4().to_string();
    db.add_shared_folder(&id, &path, true)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
