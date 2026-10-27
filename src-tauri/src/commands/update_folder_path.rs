use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn update_folder_path(
    id: String,
    new_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if new_path.len() > 1024 {
        return Err("Path too long (max 1024 characters)".into());
    }
    if new_path.contains("..") {
        return Err("Path traversal is not allowed".into());
    }

    let db = state.require_db().await?;
    db.update_folder_path(&id, &new_path)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
