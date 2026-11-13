use crate::p2p::proxy_config::{NoidProxyConfig, ProxyMode};
use crate::AppState;
use tauri::State;

/// Persist and apply the outbound proxy configuration.
#[tauri::command]
pub async fn set_proxy_config(
    state: State<'_, AppState>,
    mode: String,
    host: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    let mode = match mode.as_str() {
        "off" => ProxyMode::Off,
        "http" => ProxyMode::Http,
        "socks5" => ProxyMode::Socks5,
        other => return Err(format!("unknown proxy mode: {other}")),
    };
    let cfg = NoidProxyConfig {
        mode,
        host,
        username,
        password,
    };
    // Validate before applying: an unusable host must not wedge the dialer.
    if mode != ProxyMode::Off && cfg.to_transport().is_none() {
        return Err("invalid proxy address — expected ip:port".to_string());
    }
    // SEC-1111-10: proxy credentials encrypt at rest under the master
    // key — plaintext only when no key exists yet (pre-unlock).
    let cipher = {
        let security = state.security.lock().await;
        security
            .get_master_key()
            .ok()
            .map(crate::security::field_cipher::FieldCipher::new)
    };
    cfg.save_with_cipher(&state.app_data_dir, cipher.as_ref())?;
    cfg.apply();
    Ok(())
}
