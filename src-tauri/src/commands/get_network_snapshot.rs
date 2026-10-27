use serde::Serialize;
use tauri::State;
use crate::AppState;

/// TI-9: one-shot state snapshot for the frontend. All P2P events are
/// fire-and-forget — after a suspended/reloaded WebView the UI would only
/// learn about FUTURE connect/disconnect events. The frontend calls this
/// once after attaching listeners to rebuild `onlinePeers`, relay status
/// and its own peer id.
#[derive(Serialize)]
pub struct NetworkSnapshot {
    pub my_id: String,
    pub connected_peers: Vec<String>,
    pub relay_status: crate::p2p::RelayStatus,
}

#[tauri::command]
pub async fn get_network_snapshot(state: State<'_, AppState>) -> Result<NetworkSnapshot, String> {
    let my_id = state.my_id.lock().await.clone();
    let connected_peers: Vec<String> =
        state.connected_peers.lock().await.iter().cloned().collect();
    let relay_status = state.relay_status.lock().await.clone();
    Ok(NetworkSnapshot {
        my_id,
        connected_peers,
        relay_status,
    })
}
