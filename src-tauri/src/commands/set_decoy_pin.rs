use crate::AppState;
use tauri::State;

/// A1: enable or remove the decoy profile.
///
/// `pin = Some(p)` writes the decoy verifier (`cache/verify.hash`) — the
/// next `login(p)` opens the decoy profile instead of the real one. The
/// decoy profile itself is created lazily on the first decoy login
/// (auto-seeded — see `decoy_seeder`).
/// `pin = None` secure-deletes the whole decoy root (`cache/`), including
/// the seeded profile; the real profile is untouched.
///
/// Requires an unlocked session (master key present) — security state can
/// only change while logged in. The KillPin path is unaffected: a wipe
/// shreds the whole `data_dir`, decoy included.
#[tauri::command]
pub async fn set_decoy_pin(
    pin: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let security_arc = state.security.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let security = security_arc.blocking_lock();
        security
            .get_master_key()
            .map_err(|_| "Not logged in".to_string())?;
        match pin {
            Some(p) => {
                if p.len() < 8 || p.len() > 64 {
                    return Err("Decoy PIN must be 8–64 characters".into());
                }
                // Colliding credentials would make login ambiguous — the
                // true-PIN match wins, so a decoy equal to the true PIN
                // would silently never open the decoy; and a decoy equal
                // to the KillPin would wipe instead of decoying.
                match security.verify_true_pin(&p) {
                    Ok(true) => return Err("Decoy PIN must differ from the login PIN".into()),
                    Ok(false) => {}
                    Err(e) => return Err(e.to_string()),
                }
                if security.verify_kill_pin(&p) {
                    return Err("Decoy PIN must differ from the Kill PIN".into());
                }
                security
                    .save_decoy_pin_hash(&p)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            None => security.clear_decoy().map_err(|e| e.to_string()),
        }
    })
    .await
    .map_err(|e| format!("decoy task failed: {}", e))?
}
