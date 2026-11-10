use crate::p2p::connectivity_config::ConnectivityConfig;
use crate::AppState;
use tauri::State;

/// Update and persist the connectivity policy. The change is pushed to a
/// running node via `P2PCommand::SetConnectivityConfig` — idle teardown,
/// redial scope and ping policy apply without a restart.
#[tauri::command]
pub async fn set_connectivity_config(
    state: State<'_, AppState>,
    config: ConnectivityConfig,
) -> Result<(), String> {
    // Persist first — a crash between memory update and save would
    // otherwise silently drop the user's choice.
    config
        .save(&state.app_data_dir)
        .map_err(|e| e.to_string())?;
    *state.connectivity_config.lock().await = config.clone();

    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(
            &tx,
            crate::p2p::types::P2PCommand::SetConnectivityConfig { config },
        )
        .await;
    }
    Ok(())
}
