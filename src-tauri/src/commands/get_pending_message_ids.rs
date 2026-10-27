use crate::AppState;
use tauri::State;

/// TI-4: message ids still queued in the outbound pending table for a peer.
/// The chat view uses this to render an honest "queued" status instead of
/// the fabricated `delivered` that history reloads used to show.
#[tauri::command]
pub async fn get_pending_message_ids(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    crate::validation::parse_peer_id(&peer_id)?;
    let db = state.require_db().await?;
    db.get_pending_message_ids(&peer_id)
        .await
        .map_err(|e| e.to_string())
}
