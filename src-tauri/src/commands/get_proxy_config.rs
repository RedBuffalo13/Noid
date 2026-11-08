use crate::p2p::proxy_config::NoidProxyConfig;
use crate::AppState;
use tauri::State;

/// Return the persisted outbound proxy configuration.
#[tauri::command]
pub async fn get_proxy_config(state: State<'_, AppState>) -> Result<NoidProxyConfig, String> {
    Ok(NoidProxyConfig::load(&state.app_data_dir))
}
