use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn delete_shared_folder(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let db = state.require_db().await?;
    db.delete_shared_folder(&id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
