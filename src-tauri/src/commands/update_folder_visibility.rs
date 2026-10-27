use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn update_folder_visibility(
    id: String,
    is_public: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let db = state.require_db().await?;
    db.update_folder_visibility(&id, is_public)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
