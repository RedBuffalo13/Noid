use crate::commands::request_relay_status::request_relay_status;
use crate::p2p::RelayStatus;
use crate::AppState;
use tauri::State;

/// Return the latest relay/NAT status snapshot, fetched live from the
/// event loop (also broadcast via the `relay-status` event).
#[tauri::command]
pub async fn get_relay_status(state: State<'_, AppState>) -> Result<RelayStatus, String> {
    Ok(request_relay_status(state.inner()).await)
}
