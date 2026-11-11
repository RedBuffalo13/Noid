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
        // OPT-R03: one destructive pipeline — see run_wipe_workflow.
        crate::run_wipe_workflow(state.inner()).await?;

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
