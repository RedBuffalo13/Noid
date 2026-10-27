use crate::AppState;
use crate::{AuthOutcome, AuthResponse};
use tauri::State;

#[tauri::command]
pub async fn setup_pins(
    true_pin: String,
    kill_pin: String,
    state: State<'_, AppState>,
) -> Result<AuthResponse, String> {
    // Never trust the frontend: the PIN policy must live server-side too.
    // The frontend enforces 8+ characters; a trivially short true_pin or a
    // kill_pin identical to it would void the entire brute-force/KillPin
    // protection.
    if true_pin.len() < 8 || true_pin.len() > 64 {
        return Err("PIN must be 8–64 characters".into());
    }
    if kill_pin.len() < 8 || kill_pin.len() > 64 {
        return Err("Kill PIN must be 8–64 characters".into());
    }
    if true_pin == kill_pin {
        return Err("PIN and Kill PIN must differ".into());
    }
    // RC15: Argon2 derives (~seconds of blocking CPU) run off the tokio
    // worker; the security guard lives entirely inside the blocking task.
    // S4: re-running setup would silently rotate the master key and orphan
    // all field-encrypted data — refuse once security state exists. The
    // check sits under the security lock so concurrent setup calls race
    // on the mutex, not on filesystem state.
    let security_arc = state.security.clone();
    let key = tokio::task::spawn_blocking(move || -> Result<Option<[u8; 32]>, String> {
        let mut security = security_arc.blocking_lock();
        if security.is_setup_complete() {
            return Err("PINs are already configured".into());
        }
        security.derive_key(&true_pin).map_err(|e| e.to_string())?;
        let key = security.get_master_key().ok();
        // Phase 3.1: Save verified true_pin hash for login verification
        security
            .save_true_pin_hash(&true_pin)
            .map_err(|e| e.to_string())?;
        security
            .set_kill_pin(&kill_pin)
            .map_err(|e| e.to_string())?;
        Ok(key)
    })
    .await
    .map_err(|e| format!("setup task failed: {}", e))??;
    if let Some(key) = key {
        state.audit_log.set_key(key);
    }

    Ok(AuthResponse {
        success: true,
        message: "Setup complete".into(),
        kind: AuthOutcome::Ok,
        retry_after_secs: None,
        attempts_remaining: None,
    })
}
