use crate::db::Database;
use crate::AppState;
use crate::{AuthOutcome, AuthResponse};
use tauri::State;

#[tauri::command]
pub async fn login(pin: String, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<AuthResponse, String> {
    // KillPin must wipe even when the account is locked out — verify it
    // BEFORE the is_locked_out early-return, otherwise a locked-out user
    // can never trigger the wipe (KillPin must always work).
    // RC15: Argon2 verify is ~seconds of blocking CPU — off the tokio worker.
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
        // Close the SQLite pool BEFORE wiping — on a re-login in the same
        // process the open pool holds file locks and secure_delete fails on
        // Windows (mirrors kill_switch.rs).
        {
            let mut db_state = state.db.lock().await;
            *db_state = None;
        }
        // Stop the P2P node before wiping its keys/peer cache (see
        // kill_switch.rs) — the gate flip aborts the node task and the gate
        // task resets p2p_tx/dht_cipher/my_id/ratchet state.
        state.login_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::gate_set(&state.p2p_start_tx, false);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // RC15: secure_delete is synchronous fs work — keep it off the
        // async executor; the security guard lives only inside the task.
        let security_arc = state.security.clone();
        let wipe_result = tokio::task::spawn_blocking(move || {
            let mut security = security_arc.blocking_lock();
            security.kill_everything()
        })
        .await
        .map_err(|e| format!("wipe task failed: {}", e))?;
        wipe_result.map_err(|e| e.to_string())?;
        // Wipe the log directory too — noid.log may contain peer ids,
        // message ids and network addresses from this session.
        let log_dir = state.app_log_dir.clone();
        if log_dir.exists() {
            if let Err(e) = crate::security::secure_delete::secure_delete_dir(&log_dir) {
                log::error!("Log dir wipe failed: {}", e);
            }
        }
        {
            let auth_manager = state.auth_manager.lock().await;
            auth_manager.reset_attempts().await;
        }
        return Ok(AuthResponse {
            success: true,
            message: "WIPED".into(),
            kind: AuthOutcome::Wiped,
            retry_after_secs: None,
            attempts_remaining: None,
        });
    }

    // Lockout check AFTER the kill-pin check — a valid KillPin above already
    // wiped and returned; this rate-limits only normal PIN attempts.
    // S10: timed backoff — report the remaining wait, not a fake
    // "restart the application" (the lock used to be permanent).
    {
        let auth_manager = state.auth_manager.lock().await;
        let remaining = auth_manager.lockout_remaining_secs().await;
        if remaining > 0 {
            return Ok(AuthResponse {
                success: false,
                message: format!("Too many failed attempts. Try again in {}s", remaining),
                kind: AuthOutcome::LockedOut,
                retry_after_secs: Some(remaining),
                attempts_remaining: Some(0),
            });
        }
    }

    // Phase 3.1: Verify true PIN before deriving master key.
    // Previously derive_key returned Ok for any PIN, making the lockout dead code.
    // RC15: Argon2 verify+derive runs under spawn_blocking — the security
    // guard is confined to the blocking task and never crosses other locks.
    let pin_d = pin.clone();
    let security_arc = state.security.clone();
    let derive_result = tokio::task::spawn_blocking(move || {
        let mut security = security_arc.blocking_lock();
        match security.verify_true_pin(&pin_d) {
            Ok(true) => security.derive_key(&pin_d),
            Ok(false) => Err(anyhow::anyhow!("Invalid PIN")),
            Err(e) => Err(e), // true_pin.hash missing or corrupt
        }
    })
    .await
    .map_err(|e| format!("verify task failed: {}", e))?;

    match derive_result {
        Ok(_) => {
            // Phase E: Log successful login
            let _ = state.audit_log.log_login(true);

            let db_path = state.app_data_dir.join("noid.db");
            // A corrupt noid.db must not wedge the app in a crash loop:
            // quarantine it (the file is kept as *.corrupt-* for manual
            // recovery) and recreate against a fresh database.
            let mut database = match Database::new(&db_path).await {
                Ok(db) => db,
                Err(e) => {
                    log::error!("noid.db unreadable ({}), quarantining and recreating", e);
                    let _ = state.audit_log.log(
                        "db_quarantine",
                        "noid.db moved to .corrupt-<ts> after open failure",
                    );
                    // Sidecars (-journal/-wal/-shm) must move too — leftover
                    // ones get replayed into the fresh DB and the corruption
                    // comes straight back.
                    crate::util::quarantine::quarantine_sqlite(&db_path)
                        .map_err(|qe| format!("Failed to quarantine corrupt database: {}", qe))?;
                    Database::new(&db_path)
                        .await
                        .map_err(|e| format!("Database recreate failed: {}", e))?
                }
            };

            // Field-encryption: attach the PIN-derived master key — peer ids,
            // profile fields, private keys and ratchet states are GCM-encrypted
            // at rest; equality lookups go through deterministic HMAC columns.
            let master_key = {
                let security = state.security.lock().await;
                security.get_master_key().map_err(|e| e.to_string())?
            };
            // From now on audit details (peer ids, msg ids) are sealed at rest.
            state.audit_log.set_key(master_key);
            database
                .attach_cipher(std::sync::Arc::new(
                    crate::security::field_cipher::FieldCipher::new(master_key),
                ))
                .await
                .map_err(|e| format!("Field-encryption migration failed: {}", e))?;

            let mut db_state = state.db.lock().await;
            *db_state = Some(database);

            // Phase A.2: Initialize X3DH identity from DB (load or create)
            let mut prekey_bundle = None;
            if let Some(ref db) = *db_state {
                if let Err(e) = state.ratchet_sessions.load_identity_from_db(db).await {
                    log::error!("Failed to initialize X3DH identity: {}", e);
                }
                // Phase A.3: Generate prekeys (published once the node is up)
                match state.ratchet_sessions.generate_and_store_prekeys(db).await {
                    Ok(bundle) => {
                        log::info!("Prekeys generated successfully");
                        prekey_bundle = Some(bundle);
                    }
                    Err(e) => log::error!("Failed to generate prekeys: {}", e),
                }
            }

            {
                let auth_manager = state.auth_manager.lock().await;
                auth_manager.reset_attempts().await;
            }

            // Release the db guard BEFORE starting P2P / retry — both lock
            // state.db themselves, and tokio Mutex is not reentrant.
            drop(db_state);

            // Login-gated P2P: the node — and every listener/mailbox/DHT
            // service — exists only now, after the PIN unlocked the key store.
            state.login_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            crate::gate_set(&state.p2p_start_tx, true);

            // Publish the prekey bundle once the node installs its command
            // channel. Done in a spawned task (not inline): the node can take
            // tens of seconds to come up on slow devices, and login must not
            // block on it — a missing bundle only delays incoming ratchet
            // sessions, not the session itself.
            if let Some(bundle) = prekey_bundle {
                let p2p_tx = state.p2p_tx.clone();
                let my_id = state.my_id.clone();
                // RC12: this task can outlive a wipe+re-login inside its 60s
                // window — without the epoch check it would publish the OLD
                // session's bundle under the NEW peer id, arming desync.
                let epoch = state.login_epoch.clone();
                let epoch_at_login =
                    epoch.load(std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    for _ in 0..600 {
                        if epoch.load(std::sync::atomic::Ordering::SeqCst)
                            != epoch_at_login
                        {
                            log::debug!(
                                "Prekey publish aborted — session superseded by wipe/re-login"
                            );
                            return;
                        }
                        if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                            let peer = my_id.lock().await.clone();
                            let _ = crate::send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::PublishPrekeyBundle {
                                peer_id: peer,
                                bundle,
                            }).await;
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    log::warn!("P2P node did not come up in 60s — prekey bundle not published");
                });
            }

            // Deliver ratchet messages that arrived before login unlocked the DB
            // (offline redelivery lands seconds after P2P start, before login).
            crate::retry_undecrypted_messages(&app).await;

            Ok(AuthResponse {
                success: true,
                message: "Logged in".into(),
                kind: AuthOutcome::Ok,
                retry_after_secs: None,
                attempts_remaining: None,
            })
        }
        Err(e) => {
            // Phase E: Log failed login
            let _ = state.audit_log.log_login(false);

            let (delay, failed_count) = {
                let auth_manager = state.auth_manager.lock().await;
                let count = auth_manager.increment_failed_attempt().await;
                // S11: progressive delay on failure — this attempt may have
                // been a kill-pin guess (both pins are tried in login).
                (auth_manager.failed_attempt_delay().await, count)
            };
            tokio::time::sleep(delay).await;

            {
                let auth_manager = state.auth_manager.lock().await;
                let remaining = auth_manager.lockout_remaining_secs().await;
                if remaining > 0 {
                    return Ok(AuthResponse {
                        success: false,
                        message: format!("Too many failed attempts. Try again in {}s", remaining),
                        kind: AuthOutcome::LockedOut,
                        retry_after_secs: Some(remaining),
                        attempts_remaining: Some(0),
                    });
                }
            }

            Ok(AuthResponse {
                success: false,
                message: e.to_string(),
                kind: AuthOutcome::Failed,
                retry_after_secs: None,
                attempts_remaining: Some(
                    crate::auth::LOCKOUT_THRESHOLD.saturating_sub(failed_count),
                ),
            })
        }
    }
}
