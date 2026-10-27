use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn reconnect_to_contacts(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let db = state.require_db().await?;
    // Get all contacts to reconnect to
    let contacts = db.get_contacts().await.map_err(|e| e.to_string())?;

    // RC17: silent Ok with no node made the reconnect a reported no-op.
    let tx = state.require_p2p()?;
    for (peer_id, _, _) in contacts {
        let _ = crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::ConnectToPeer {
            peer_id,
            addr_hint: None,
        }).await.map_err(|e| e.to_string());
    }

    Ok(())
}
