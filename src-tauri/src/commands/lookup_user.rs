use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn lookup_user(
    username: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("username", &username, 64)?;
    log::debug!("lookup_user: looking up username '{}'", username);
    if let Some(tx) = state.p2p() {
        crate::send_p2p_cmd(&tx, P2PCommand::LookupUser { username })
            .await
            .map_err(|e| e.to_string())?;
    } else {
        log::warn!("lookup_user: P2P not initialized");
        return Err("P2P not initialized".into());
    }
    Ok(())
}
