use crate::AppState;
use tauri::State;

/// Deletes the direct-chat history with `peer_id` (messages + undelivered
/// outbox). The contact itself and the ratchet session are kept — a chat can
/// be cleared without losing the peer.
#[tauri::command]
pub async fn delete_chat(peer_id: String, state: State<'_, AppState>) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    let db = state.require_db().await?;
    db.delete_chat(&peer_id).await.map_err(|e| e.to_string())?;
    Ok(())
}
