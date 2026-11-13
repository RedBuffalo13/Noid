use crate::AppState;
use tauri::State;

/// A1: whether a decoy profile PIN is configured (`cache/verify.hash`).
/// Lets the settings UI show enable vs remove without probing files.
#[tauri::command]
pub async fn is_decoy_configured(state: State<'_, AppState>) -> Result<bool, String> {
    let security = state.security.lock().await;
    Ok(security.is_decoy_configured())
}
