use crate::p2p::{PrivacyMode, RelayConfig};
use crate::AppState;
use tauri::State;

/// Persist a new privacy mode (`direct` | `relayed_only`).
/// In `relayed_only` the node does not advertise direct addresses and only
/// dials via circuit relays — peers see the relay's IP, not ours.
/// The change takes effect on the next app start.
#[tauri::command]
pub async fn set_privacy_mode(
    mode: String,
    state: State<'_, AppState>,
) -> Result<RelayConfig, String> {
    let new_mode = match mode.as_str() {
        "direct" => PrivacyMode::Direct,
        "relayed_only" => PrivacyMode::RelayedOnly,
        other => {
            return Err(format!(
                "Invalid privacy mode '{other}' — expected direct|relayed_only"
            ))
        }
    };

    let mut cfg = state.relay_config.lock().await;
    cfg.privacy = new_mode;
    cfg.save(&state.app_data_dir).map_err(|e| e.to_string())?;
    log::info!("Privacy mode set to {:?} (applies after restart)", new_mode);
    Ok(cfg.clone())
}
