use crate::p2p::tor::config::{load, TOR_CONFIG_SCHEMA_VERSION};
use crate::p2p::tor::status::TorStatus;
use crate::AppState;
use tauri::State;

/// P5: opt the node in/out of serving onion circuits for other peers.
///
/// Both switches are persisted separately from the Tor consent: a mobile
/// relay is its own traffic/battery decision, and `allow_metered` is the
/// second, explicit consent required before any relayed byte may travel on
/// a metered network. The node is recreated so the new relay limits apply
/// — `login_epoch` is untouched.
///
/// Budgets are fixed in `relay_config::to_onion_relay_config` (≤4
/// reservations, ≤2 circuits, 32 MiB, 30 min) — tighter than the WAN
/// profile; a mobile relay can never soak the battery.
#[tauri::command]
pub async fn set_tor_relay(
    enabled: bool,
    allow_metered: bool,
    state: State<'_, AppState>,
) -> Result<TorStatus, String> {
    log::info!("set_tor_relay: enabled={} allow_metered={}", enabled, allow_metered);
    let path = state
        .app_data_dir
        .join("tor")
        .join("tor_config.json");
    let mut cfg = load(&path).unwrap_or_default();
    cfg.schema_version = TOR_CONFIG_SCHEMA_VERSION;
    cfg.onion_relay_enabled = enabled;
    cfg.allow_metered_relay = allow_metered;
    cfg.save(&path).map_err(|e| e.to_string())?;
    // Node-only restart so build_swarm rebuilds relay::Config with the
    // onion budget — same mechanism as set_tor_mode.
    state
        .network_generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    crate::gate_set(&state.p2p_start_tx, false);
    let tx = state.p2p_start_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        crate::gate_set(&tx, true);
    });
    Ok(state.tor.status())
}
