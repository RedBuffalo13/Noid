use crate::p2p::RelayConfig;
use crate::AppState;
use tauri::State;

/// META-05: pin the 2-hop privacy relay chain `[entry, exit]`.
///
/// Each element is a PeerId string or a full multiaddr ending in
/// `/p2p/<peer_id>`. An empty list disables hop routing (direct/single-hop
/// behaviour). The change applies to new sends immediately — no restart.
#[tauri::command]
pub async fn set_hop_relays(
    relays: Vec<String>,
    state: State<'_, AppState>,
) -> Result<RelayConfig, String> {
    if relays.len() > 2 {
        return Err("hop chain supports at most 2 relays [entry, exit]".to_string());
    }
    for r in &relays {
        let ok_peer = r.parse::<libp2p::PeerId>().is_ok();
        let ok_addr = r
            .parse::<libp2p::Multiaddr>()
            .map(|a| {
                a.iter()
                    .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
            })
            .unwrap_or(false);
        if !ok_peer && !ok_addr {
            return Err(format!("invalid hop relay '{r}' — expected PeerId or /p2p multiaddr"));
        }
    }
    let mut cfg = state.relay_config.lock().await;
    cfg.hop_relays = relays.clone();
    cfg.save(&state.app_data_dir).map_err(|e| e.to_string())?;
    // Push into the live node — new sends route through the chain
    // immediately; no restart needed unlike role/privacy changes.
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::SetHopRelays { relays }).await;
    }
    Ok(cfg.clone())
}
