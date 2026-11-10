use crate::p2p::tor::mode::TorMode;
use crate::p2p::tor::status::TorStatus;
use crate::AppState;
use tauri::State;

/// Set the desired Tor mode and restart ONLY the P2P node so it picks up
/// the new effective policy (direct transports on/off, onion transport).
///
/// - `mode`: "off" | "additional" | "tor_only" — anything else is refused.
/// - `consent_version`: the version of the Tor consent text the user
///   accepted; 0 means never consented and the supervisor will refuse to
///   start Tor (identity stays offline, status carries
///   `consent_required`).
///
/// `login_epoch` is NOT touched — identity, contacts, ratchet sessions,
/// rooms and the outbox all survive a mode change. `network_generation`
/// is bumped for observability; the gate flip aborts the node task and
/// the gate watcher rebuilds it with the new policy.
#[tauri::command]
pub async fn set_tor_mode(
    mode: String,
    consent_version: u32,
    state: State<'_, AppState>,
) -> Result<TorStatus, String> {
    let parsed = match mode.as_str() {
        "off" => TorMode::Off,
        "additional" => TorMode::Additional,
        "tor_only" => TorMode::TorOnly,
        other => return Err(format!("unknown tor mode: {}", other)),
    };
    log::info!("set_tor_mode: mode={:?} consent_version={}", parsed, consent_version);
    state
        .tor
        .set_desired(parsed, consent_version)
        .await
        .map_err(|e| e.to_string())?;
    // Persist the choice — relay flags already live in tor_config.json;
    // without this the mode/consent reset on every restart.
    {
        let cfg_path = state.tor.dir().join("tor_config.json");
        let mut cfg = crate::p2p::tor::config::load(&cfg_path).unwrap_or_default();
        cfg.mode = parsed;
        cfg.consent_version = consent_version;
        if let Err(e) = cfg.save(&cfg_path) {
            log::warn!("tor_config.json persist failed: {}", e);
        }
    }
    state
        .network_generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // Node-only restart: close the gate so the event-loop task exits, then
    // reopen — the gate watcher rebuilds the node with the effective
    // policy. Identity/state are untouched.
    crate::gate_set(&state.p2p_start_tx, false);
    let tx = state.p2p_start_tx.clone();
    tokio::spawn(async move {
        // Let the abort land before reopening — the watcher seq-checks so
        // a fast flip is not lost.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        crate::gate_set(&tx, true);
    });
    Ok(state.tor.status())
}
