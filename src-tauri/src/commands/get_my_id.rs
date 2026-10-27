use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_my_id(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.my_id.lock().await.clone())
}
