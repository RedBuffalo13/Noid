use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn check_username(
    username: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("username", &username, 64)?;
    // P2P down must be an error, not a silent Ok — otherwise the frontend
    // resolves the availability check as success while nothing was queried.
    let tx = state.p2p().ok_or("P2P network not initialized")?;
    crate::send_p2p_cmd(&tx, P2PCommand::CheckUsernameAvailability { username })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
