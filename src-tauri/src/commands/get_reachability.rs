use crate::AppState;
use tauri::State;

/// Reachability level + dialable path classes for a peer — computed
/// inside the node (needs swarm/cache state), returned to the UI as the
/// presence model replacing binary online/offline.
#[tauri::command]
pub async fn get_reachability(
    state: State<'_, AppState>,
    peer_id: String,
) -> Result<serde_json::Value, String> {
    let tx = state.p2p().ok_or("P2P node not running")?;
    let (rtx, rrx) = tokio::sync::oneshot::channel();
    crate::send_p2p_cmd(
        &tx,
        crate::p2p::types::P2PCommand::ReachabilityQuery {
            peer_id,
            respond_to: rtx,
        },
    )
    .await?;
    rrx.await.map_err(|_| "node dropped the query".to_string())
}
