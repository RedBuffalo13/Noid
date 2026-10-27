use crate::p2p::{invite, P2PCommand};
use crate::AppState;
use tauri::State;

/// Join the network / reach a peer by address.
///
/// Accepts a full invite (`noid:<peer>@<addr,...>`), a bare multiaddr, or a
/// bare peer id (DHT lookup fallback). This is the cold-start entry point:
/// dialing a reachable node merges our DHT with theirs.
#[tauri::command]
pub async fn connect_to_addr(
    input: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let parsed = invite::parse_invite(&input)?;

    if let Some(tx) = state.p2p() {
        for addr in &parsed.addrs {
            crate::send_p2p_cmd(&tx, P2PCommand::DialAddress { addr: addr.clone() })
                .await
                .map_err(|e| e.to_string())?;
        }
        // Queue a DHT lookup too — works once any connection is up.
        crate::send_p2p_cmd(&tx, P2PCommand::ConnectToPeer {
            peer_id: parsed.peer_id.clone(),
            addr_hint: None,
        })
        .await
        .map_err(|e| e.to_string())?;
        Ok(parsed.peer_id)
    } else {
        Err("P2P not initialized".to_string())
    }
}
