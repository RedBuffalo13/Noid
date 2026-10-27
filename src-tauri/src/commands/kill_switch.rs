use crate::AppState;
use crate::{AuthOutcome, AuthResponse};
use tauri::State;

#[tauri::command]
pub async fn kill_switch(pin: String, state: State<'_, AppState>) -> Result<AuthResponse, String> {
    // KillPin must work even under lockout — verify BEFORE the rate-limit
    // early-return, or a locked-out user can never wipe.
    // RC15: Argon2 verify is blocking CPU — off the tokio worker.
    let pin_k = pin.clone();
    let security_arc = state.security.clone();
    let is_kill_pin = tokio::task::spawn_blocking(move || {
        let security = security_arc.blocking_lock();
        security.verify_kill_pin(&pin_k)
    })
    .await
    .map_err(|e| format!("verify task failed: {}", e))?;

    if is_kill_pin {
        // Phase E: Log kill-switch activation before wiping
        let _ = state.audit_log.log_kill_pin();

        // Phase 3.4: Close DB pool before wipe to avoid file lock conflicts
        {
            let mut db_state = state.db.lock().await;
            *db_state = None; // Drop the Database, closing the SQLite pool
        }
        log::info!("Database pool closed before wipe");

        // Stop the P2P node before wiping its keys/peer cache: flipping the
        // login gate to false aborts the node task, which drops the mailbox.db
        // pool and closes the event channel — then the gate task resets
        // p2p_tx/dht_cipher/my_id/ratchet state for a clean re-login.
        // RC12: bump the login epoch so any surviving spawn (prekey publish,
        // retry workers) aborts instead of writing into the wiped session.
        state.login_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::gate_set(&state.p2p_start_tx, false);
        // Give the abort + pool drop a moment so secure_delete does not hit
        // file locks on Windows.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // RC15: secure_delete is synchronous fs work — off the executor.
        let security_arc = state.security.clone();
        let wipe_result = tokio::task::spawn_blocking(move || {
            let mut security = security_arc.blocking_lock();
            security.kill_everything()
        })
        .await
        .map_err(|e| format!("wipe task failed: {}", e))?;
        wipe_result.map_err(|e| {
            log::error!("Secure delete failed: {}", e);
            e.to_string()
        })?;

        // Wipe the log directory too — noid.log may contain peer ids,
        // message ids and network addresses from this session.
        let log_dir = state.app_log_dir.clone();
        if log_dir.exists() {
            if let Err(e) = crate::security::secure_delete::secure_delete_dir(&log_dir) {
                log::error!("Log dir wipe failed: {}", e);
            }
        }

        Ok(AuthResponse {
            success: true,
            message: "System Wiped".into(),
            kind: AuthOutcome::Wiped,
            retry_after_secs: None,
            attempts_remaining: None,
        })
    } else {
        // Phase 3.4: Increment failed attempts for kill pin
        // S11: the most destructive secret had the weakest rate-limit —
        // unlimited Argon2-speed guessing (~1 try/s). Progressive delay:
        // 2^failures seconds (cap 64s) before the wrong answer is returned.
        // A correct kill pin still wipes instantly (checked above).
        let delay = {
            let auth_manager = state.auth_manager.lock().await;
            auth_manager.increment_failed_attempt().await;
            auth_manager.failed_attempt_delay().await
        };
        tokio::time::sleep(delay).await;
        Err("Invalid KillPin".into())
    }
}
