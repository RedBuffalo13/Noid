use crate::p2p::RelayConfig;
use crate::AppState;
use tauri::State;

/// Return the persisted relay configuration (role, privacy, limits).
#[tauri::command]
pub async fn get_relay_config(state: State<'_, AppState>) -> Result<RelayConfig, String> {
    Ok(state.relay_config.lock().await.clone())
}
