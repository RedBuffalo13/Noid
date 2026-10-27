use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn validate_peer_id(peer_id: String, _state: State<'_, AppState>) -> Result<bool, String> {
    // Try to parse the peer ID to validate it
    match peer_id.parse::<libp2p::PeerId>() {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
