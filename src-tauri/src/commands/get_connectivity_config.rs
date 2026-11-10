use crate::p2p::connectivity_config::ConnectivityConfig;
use crate::AppState;
use tauri::State;

/// Return the persisted connectivity policy (on-demand flag, TTLs).
#[tauri::command]
pub async fn get_connectivity_config(
    state: State<'_, AppState>,
) -> Result<ConnectivityConfig, String> {
    Ok(state.connectivity_config.lock().await.clone())
}
