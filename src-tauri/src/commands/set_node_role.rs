use crate::p2p::{NodeRole, RelayConfig};
use crate::AppState;
use tauri::State;

/// Persist a new node role (`auto` | `relay` | `client`).
/// The change takes effect on the next app start, when the swarm is built.
#[tauri::command]
pub async fn set_node_role(role: String, state: State<'_, AppState>) -> Result<RelayConfig, String> {
    let new_role = match role.as_str() {
        "auto" => NodeRole::Auto,
        "relay" => NodeRole::Relay,
        "client" => NodeRole::Client,
        other => return Err(format!("Invalid node role '{other}' — expected auto|relay|client")),
    };

    let mut cfg = state.relay_config.lock().await;
    cfg.role = new_role;
    cfg.save(&state.app_data_dir).map_err(|e| e.to_string())?;
    log::info!("Node role set to {:?} (applies after restart)", new_role);
    Ok(cfg.clone())
}
