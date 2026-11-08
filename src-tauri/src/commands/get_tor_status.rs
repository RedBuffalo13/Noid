use crate::p2p::tor::config::load;
use crate::p2p::tor::status::TorStatus;
use crate::AppState;
use tauri::State;

/// Latest Tor status snapshot. `state == "unsupported"` when built without
/// `embedded-tor` or under `NOID_DISABLE_TOR=1`; never carries secrets or
/// raw peer endpoints (onion address is our own, only when identity exists).
/// `relay_enabled`/`allow_metered_relay` are the PERSISTED config flags so
/// the settings UI can restore the toggles — `relay_active` is the runtime
/// gate and stays unset until a generation is actually running.
#[tauri::command]
pub async fn get_tor_status(state: State<'_, AppState>) -> Result<TorStatus, String> {
    let mut s = state.tor.status();
    let cfg = load(&state.app_data_dir.join("tor").join("tor_config.json"))
        .unwrap_or_default();
    s.relay_enabled = cfg.onion_relay_enabled;
    s.allow_metered_relay = cfg.allow_metered_relay;
    // `relay_active` was never populated in supervisor status — dead field,
    // always false. The runtime gate (flag + consent + running generation)
    // is exactly what `onion_relay_enabled()` computes.
    s.relay_active = state.tor.onion_relay_enabled();
    Ok(s)
}
