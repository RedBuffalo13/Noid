use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn is_first_run(state: State<'_, AppState>) -> Result<bool, String> {
    let kill_pin_path = state.app_data_dir.join("kill.hash");
    Ok(!kill_pin_path.exists())
}
