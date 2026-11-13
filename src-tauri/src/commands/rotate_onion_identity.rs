//! SEC-1111-05: rotate the embedded onion identity — new `.onion` address.
//! The old service generation is dropped and the persisted hsid key
//! material is erased before a fresh identity is generated.

use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn rotate_onion_identity(state: State<'_, AppState>) -> Result<String, String> {
    let master_key = {
        let security = state.security.lock().await;
        security.get_master_key().map_err(|e| e.to_string())?
    };
    // Remember the desired mode: rotation drops the running generation, so
    // an active Tor user expects the service back under a new address.
    let mode = state.tor.status().desired_mode;
    let addr = state
        .tor
        .rotate_onion_identity(&master_key)
        .map_err(|e| e.to_string())?;
    if mode != crate::p2p::tor::mode::TorMode::Off {
        // Reuse the persisted consent — the user already accepted Tor; a
        // fresh consent prompt on every rotation would be wrong.
        let cfg_path = state.tor.dir().join("tor_config.json");
        let consent = crate::p2p::tor::config::load(&cfg_path)
            .map(|c| c.consent_version)
            .unwrap_or(0);
        if let Err(e) = state.tor.set_desired(mode, consent).await {
            log::warn!("onion service relaunch after rotation failed: {}", e);
        }
    }
    let _ = state
        .audit_log
        .log("onion_identity_rotated", "hsid key material rotated");
    Ok(addr)
}
