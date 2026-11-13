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
    // The kill and true verifies are independent hash computations — run
    // them on two threads so the lockout gate costs one Argon2, not two.
    let pin_k = pin.clone();
    let security_arc = state.security.clone();
    let (is_kill_pin, true_pin_ok, decoy_pin_ok) = tokio::task::spawn_blocking(move || {
        let security = security_arc.blocking_lock();
        let sec = &security;
        std::thread::scope(|s| {
            let pk = pin_k.clone();
            let kill = s.spawn(move || sec.verify_kill_pin(&pk));
            let pt = pin_k.clone();
            let tru = s.spawn(move || match sec.verify_true_pin(&pt) {
                Ok(v) => Ok(v),
                Err(e) => Err(e.to_string()),
            });
            // A1: the decoy slot runs on a third thread — wall-time is one
            // Argon2 regardless of which verifier matches, so the login
            // latency reveals nothing about profile choice.
            let pd = pin_k.clone();
            let dec = s.spawn(move || sec.verify_decoy_pin(&pd));
            let k = kill.join().unwrap_or(false);
            let t = tru.join().unwrap_or(Ok(false));
            let d = dec.join().unwrap_or(None);
            (k, t, d)
        })
    })
    .await
    .map_err(|e| format!("verify task failed: {}", e))?;

    if is_kill_pin {
        // OPT-R03: one destructive pipeline — see run_wipe_workflow.
        crate::run_wipe_workflow(state.inner()).await?;
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

    // Phase 3.1: The true PIN was already verified in parallel with the
    // kill check above — only the key derivation remains.
    // RC15: Argon2 derive runs under spawn_blocking — the security
    // guard is confined to the blocking task and never crosses other locks.
    // A1: a true-PIN match wins over a decoy match (they can never be the
    // same string — setup enforces it, but never trust the invariant).
    let is_decoy_login =
        !matches!(true_pin_ok, Ok(true)) && matches!(decoy_pin_ok, Some(true));
    let pin_d = pin.clone();
    let security_arc = state.security.clone();
    let derive_result = tokio::task::spawn_blocking(move || {
        let mut security = security_arc.blocking_lock();
        if is_decoy_login {
            return security.derive_decoy_key(&pin_d);
        }
        match true_pin_ok {
            Ok(true) => security.derive_key(&pin_d),
            Ok(false) => Err(anyhow::anyhow!("Invalid PIN")),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    })
    .await
    .map_err(|e| format!("verify task failed: {}", e))?;

    match derive_result {
        Ok(_) => {
            // Phase E: Log successful login — into the ACTIVE profile's
            // audit log (decoy sessions keep their own).
            let profile_root = if is_decoy_login {
                let security = state.security.lock().await;
                security.decoy_dir()
            } else {
                state.app_data_dir.clone()
            };
            state
                .audit_log
                .retarget(profile_root.join("audit.log"));
            let _ = state.audit_log.log_login(true);
            state
                .is_decoy
                .store(is_decoy_login, std::sync::atomic::Ordering::Relaxed);

            let db_path = profile_root.join("noid.db");
            // A corrupt noid.db must not wedge the app in a crash loop:
            // quarantine it (the file is kept as *.corrupt-* for manual
            // recovery) and recreate against a fresh database.
            let mut database = match Database::new(&db_path).await {
                Ok(db) => db,
                Err(e) => {
                    // SEC-A07: quarantine only on evidence of actual
                    // corruption. Transient I/O, file locks, permissions
                    // and incompatible/newer schema now surface the error
                    // instead of moving the user's database aside.
                    let msg = e.to_string().to_lowercase();
                    let corrupt = ["malformed", "not a database", "corrupt",
                        "database disk image"]
                        .iter()
                        .any(|m| msg.contains(m));
                    if !corrupt {
                        log::error!("noid.db open failed without corruption evidence: {}", e);
                        return Err(format!(
                            "Database unavailable (file left untouched): {}",
                            e
                        ));
                    }
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
            // Offline onion identity: creates/opens the encrypted keystore
            // only — no Tor sockets, no bootstrap, no descriptor. Failure is
            // non-fatal: Tor stays disabled and can retry on next login.
            // A1: decoy sessions never touch the REAL tor keystore — the
            // onion identity is profile-bound, so Tor stays off in decoy.
            if !is_decoy_login {
            if let Err(e) = state.tor.ensure_identity(&master_key) {
                log::warn!("onion identity ensure failed (Tor stays off): {}", e);
            }
            // Restore the persisted Tor mode: tor_config.json survives the
            // restart, so a user who left Tor on does not have to re-toggle
            // it every session. Requires nonzero consent (set_desired
            // refuses 0) and a non-off mode; identity must exist — it was
            // just ensured above. Identity/session state untouched.
            {
                let cfg = crate::p2p::tor::config::load(
                    &state.app_data_dir.join("tor").join("tor_config.json"),
                )
                .unwrap_or_default();
                if cfg.mode != crate::p2p::tor::mode::TorMode::Off && cfg.consent_version > 0 {
                    log::info!("Restoring persisted Tor mode {:?} (consent {})", cfg.mode, cfg.consent_version);
                    if let Err(e) = state.tor.set_desired(cfg.mode, cfg.consent_version).await {
                        log::error!("Persisted Tor mode restore failed: {}", e);
                    }
                }
            }
            }
            database
                .attach_cipher(std::sync::Arc::new(
                    crate::security::field_cipher::FieldCipher::new(master_key),
                ))
                .await
                .map_err(|e| format!("Field-encryption migration failed: {}", e))?;

            let mut db_state = state.db.lock().await;
            *db_state = Some(database);

            // A1/V5: auto-populate a fresh decoy profile — contacts, a room
            // or two and mundane history — so it opens looking used, not
            // empty. The decoy PeerId is resolved from the decoy
            // `identity.key` (non-strict regen: a corrupt decoy key mints a
            // fresh plausible identity; the supervisor's strict load then
            // succeeds because the file was already rewritten).
            if is_decoy_login {
                let decoy_peer = {
                    let dir = profile_root.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut regenerated = false;
                        crate::security::key_store::load_or_regen(
                            &dir.join("identity.key"),
                            &master_key,
                            || {
                                libp2p::identity::Keypair::generate_ed25519()
                                    .to_protobuf_encoding()
                                    .map_err(|e| anyhow::anyhow!("keypair encode: {}", e))
                            },
                            |raw| libp2p::identity::Keypair::from_protobuf_encoding(raw).is_ok(),
                            &mut regenerated,
                        )
                        .ok()
                        .and_then(|b| {
                            libp2p::identity::Keypair::from_protobuf_encoding(&b).ok()
                        })
                        .map(|k| k.public().to_peer_id().to_string())
                    })
                    .await
                    .ok()
                    .flatten()
                };
                if let (Some(db), Some(peer)) = (db_state.as_ref(), decoy_peer) {
                    let security = state.security.lock().await;
                    if let Err(e) =
                        crate::security::decoy_seeder::seed_decoy_profile(db, &security, &peer).await
                    {
                        log::warn!("decoy seeding failed (profile stays empty): {}", e);
                    }
                }
            }

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
                // SEC-1111-09: tracked — KillPin drains it via session_tasks.
                let h = tokio::spawn(async move {
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
                state.session_tasks.lock().await.push(h);
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
