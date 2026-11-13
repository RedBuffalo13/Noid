use crate::p2p::proxy_config::NoidProxyConfig;
use crate::AppState;
use tauri::State;

/// Return the persisted outbound proxy configuration.
#[tauri::command]
pub async fn get_proxy_config(state: State<'_, AppState>) -> Result<NoidProxyConfig, String> {
    let cipher = {
        let security = state.security.lock().await;
        security
            .get_master_key()
            .ok()
            .map(crate::security::field_cipher::FieldCipher::new)
    };
    Ok(NoidProxyConfig::load_with_cipher(
        &state.app_data_dir,
        cipher.as_ref(),
    ))
}
