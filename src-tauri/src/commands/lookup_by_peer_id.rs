use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn lookup_by_peer_id(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    log::debug!("lookup_by_peer_id: looking up peer {}", peer_id);

    if peer_id.parse::<libp2p::PeerId>().is_err() {
        log::warn!("lookup_by_peer_id: invalid peer ID format: {}", peer_id);
        return Err("Invalid Peer ID format".into());
    }

    if let Some(tx) = state.p2p() {
        crate::send_p2p_cmd(&tx, P2PCommand::ConnectToPeer {
            peer_id: peer_id.clone(),
            addr_hint: None,
        })
        .await
        .map_err(|e| e.to_string())?;

        // D18: report the actual connectivity, not "the dial was queued" —
        // the UI painted unreachable peers as online. isOnline becomes true
        // via the peer-online event once ConnectionEstablished lands.
        let connected = state.connected_peers.lock().await.contains(&peer_id);
        log::debug!("lookup_by_peer_id: connect command sent for peer {} (connected={})", peer_id, connected);
        Ok(connected)
    } else {
        Err("P2P not initialized".into())
    }
}
