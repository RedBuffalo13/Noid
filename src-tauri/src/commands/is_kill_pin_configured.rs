use crate::AppState;
use tauri::State;

/// Whether a KillPin verifier exists — the UI shows a persistent warning
/// when remote wipe is unavailable.
#[tauri::command]
pub async fn is_kill_pin_configured(state: State<'_, AppState>) -> Result<bool, String> {
    // S18: existence alone lied — a corrupt kill.hash left the UI showing
    // "wipe available" while no PIN could ever verify. Require a parseable
    // PHC hash, not just a file.
    let path = state.app_data_dir.join("kill.hash");
    let configured = std::fs::read_to_string(&path)
        .map(|s| argon2::PasswordHash::new(&s).is_ok())
        .unwrap_or(false);
    Ok(configured)
}
