//! Receives an X3DHInit control message and installs the responder-side
//! ratchet session (init_bob). Shared by the direct request/response path
//! and the mailbox retrieval path — a desynced pair re-handshakes through
//! whichever transport delivers the init first.

use tauri::Manager;

use crate::{decode_pending_content, p2p_sender, AppState};

/// Complete the X3DH handshake as responder for `from`, then flush any
/// pending outbound queue under the fresh session.
pub(crate) async fn handle_x3dh_init(
    handle: &tauri::AppHandle,
    from: String,
    identity_public: &[u8],
    ephemeral_public: &[u8],
    one_time_prekey_id: &Option<Vec<u8>>,
    identity_signature: &[u8],
) {
    log::debug!(
        "Received X3DH init from {} (identity: {} bytes, ephemeral: {} bytes, otpk_id: {})",
        from,
        identity_public.len(),
        ephemeral_public.len(),
        one_time_prekey_id.as_ref().map(|v| v.len()).unwrap_or(0)
    );

    let app_state = handle.state::<AppState>();

    // S21: the init's X3DH identity key must be attested by the sender's
    // Noise identity — otherwise a peer can pin our session under an
    // arbitrary key and hold two divergent views of the contact.
    if !identity_signature.is_empty() {
        let payload =
            crate::p2p::types::x3dh_init_signing_payload(identity_public, ephemeral_public);
        if !crate::security::identity_sig::verify_payload(&from, &payload, identity_signature) {
            log::warn!("X3DHInit from {} rejected — invalid identity signature", from);
            return;
        }
    } else {
        log::warn!("X3DHInit from {} has no identity signature (legacy peer)", from);
    }

    let sessions = app_state.ratchet_sessions.clone();

    let initial_msg = crate::security::x3dh::InitialMessage {
        identity_public: identity_public.to_vec(),
        ephemeral_public: ephemeral_public.to_vec(),
        one_time_prekey_id: one_time_prekey_id.clone(),
    };

    // RC2: snapshot the Database (shared pool) instead of holding the
    // global db mutex across receive_session/audit_log/my_id locks.
    let db = match app_state.db.lock().await.clone() {
        Some(db) => db,
        None => {
            log::warn!("DB not initialized — cannot complete X3DH");
            return;
        }
    };

    // 1. Load signed prekey secret from DB
    let (spk_priv_bytes, db_for_consume) = match db.get_signed_prekey().await {
        Ok(Some((_, bytes))) => (bytes, db),
        Ok(None) => {
            log::warn!("No signed prekey found in DB — cannot complete X3DH");
            return;
        }
        Err(e) => {
            log::error!("Failed to load signed prekey: {}", e);
            return;
        }
    };
    let spk_secret_bytes: [u8; 32] = match spk_priv_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            log::error!("Invalid signed prekey length in DB");
            return;
        }
    };
    let spk_secret = x25519_dalek::StaticSecret::from(spk_secret_bytes);

    // F15/CR-04: freshness BEFORE the OTPK lookup — a replayed verbatim
    // X3DHInit arriving after its OTPK was consumed must be rejected as a
    // duplicate, not reported as "missing OTPK". And CR-05/MD-03: the gate
    // uses `is_desynced` (pure read) instead of `should_rehandshake` — the
    // latter also MARKS an attempt, so an inbound init from a desynced peer
    // armed our rate limit and then rejected the very init that healed it.
    // Re-handshake stays open when: no session, the session is desynced, or
    // it is still UNCONFIRMED (handshake glare — both sides initiated as
    // Alice; the inbound init wins and resolves the pair).
    let has_session = sessions.has_session(&from).await;
    if has_session
        && sessions.is_confirmed(&from).await
        && !sessions.is_desynced(&from).await
    {
        log::warn!(
            "X3DHInit from {} rejected — confirmed healthy session already exists (replay?)",
            from
        );
        return;
    }
    if has_session {
        // Glare (unconfirmed outgoing session) or desync — drop the loser
        // so receive_session installs a consistent pair.
        sessions.drop_session(&from).await;
    }

    // 2. Load one-time prekey secret WITHOUT consuming it yet.
    // Fail closed: when the initiator referenced an OTPK we no longer hold,
    // continuing would derive a session WITHOUT DH4 while the initiator
    // included it — both sides end up with different keys and every ratchet
    // message undecryptable. Reject instead of desyncing.
    let otpk_secret = if let Some(ref otpk_pub) = one_time_prekey_id {
        match db_for_consume.get_one_time_prekey(otpk_pub).await {
            Ok(Some(priv_bytes)) => {
                let priv_arr: [u8; 32] = match priv_bytes.as_slice().try_into() {
                    Ok(b) => b,
                    Err(_) => {
                        log::warn!("Invalid one-time prekey length");
                        return;
                    }
                };
                Some(x25519_dalek::StaticSecret::from(priv_arr))
            }
            Ok(None) => {
                log::warn!(
                    "X3DH init references unavailable one-time prekey — rejecting handshake from {}",
                    from
                );
                // MD-09: our published bundle advertised an OTPK we no
                // longer hold — republish a fresh pool so the initiator's
                // next attempt hits a live key instead of the same wall.
                spawn_prekey_replenish(handle);
                return;
            }
            Err(e) => {
                log::error!("Failed to load one-time prekey: {}", e);
                return;
            }
        }
    } else {
        None
    };

    // 3. Receive session
    let otpk_ref = otpk_secret.as_ref();
    if let Err(e) = sessions
        .receive_session(&from, &initial_msg, &spk_secret, otpk_ref)
        .await
    {
        log::error!("Failed to receive X3DH session from {}: {}", from, e);
        return;
    }
    log::debug!("X3DH session established with {}", from);
    // A fresh handshake replaces any desynced state — reset the
    // decrypt-failure bookkeeping so the re-handshake gate can arm again.
    sessions.note_decrypt_success(&from).await;
    // Consume the OTPK only now that the session is installed — a failed
    // receive must not burn keys.
    if let Some(ref otpk_pub) = one_time_prekey_id {
        if let Err(e) = db_for_consume.consume_one_time_prekey(otpk_pub).await {
            log::warn!("Failed to mark one-time prekey consumed: {}", e);
        }
    }
    // S1: republish the prekey bundle when the pool runs low — every
    // consumed OTPK used to shorten the advertised pool until re-login,
    // letting stale-bundle inits fail-close all later handshakes.
    if let Ok(remaining) = db_for_consume.get_one_time_prekey_count().await {
        if remaining < 5 {
            spawn_prekey_replenish(handle);
        }
    }
    let _ = app_state.audit_log.log_key_exchange(&from);
    if let Err(e) = sessions.save_session(&db_for_consume, &from).await {
        log::error!("Failed to save ratchet session: {}", e);
    }

    // MD-06: inbound ratchet messages that arrived before this session
    // existed were parked in `undecrypted_inbound` — drain them now that
    // the session is installed instead of waiting for the next trigger.
    crate::retry_undecrypted_messages(handle).await;

    // Auto-retry pending messages now that the session is established.
    let db_for_retry = app_state.db.clone();
    let sessions_for_retry = sessions.clone();
    let p2p_tx_for_retry = app_state.p2p_tx.clone();
    let security_for_retry = app_state.security.clone();
    let my_id_for_retry = app_state.my_id.lock().await.clone();
    let peer_id_for_retry = from;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // RC2: snapshot — decode_pending_content locks `security` below.
        let db = db_for_retry.lock().await.clone();
        if let Some(db) = db {
            if let Ok(pending) = db.get_pending_messages(&peer_id_for_retry).await {
                for (id, raw_content, message_id) in pending {
                    let Some(content) =
                        decode_pending_content(&security_for_retry, &raw_content).await
                    else {
                        log::warn!("Pending row {} undecryptable — skipped", id);
                        continue;
                    };
                    if let Some(json) = content.strip_prefix("NOIDMSG1:") {
                        if let Ok(msg) = serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                // Keep the row until MessageDelivered —
                                // send() only queues.
                                let _ = crate::send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                        peer_id: peer_id_for_retry.clone(),
                                        msg,
                                    })
                                    .await;
                            }
                        }
                        continue;
                    }
                    match sessions_for_retry
                        .encrypt(&peer_id_for_retry, content.as_bytes())
                        .await
                    {
                        Ok(Some(ratchet_msg)) => {
                            let noid_msg = crate::p2p::types::NoidMessage {
                                id: message_id.clone(),
                                sender: my_id_for_retry.clone(),
                                content: String::new(),
                                msg_type: crate::p2p::types::MessageType::RatchetChat {
                                    ciphertext: ratchet_msg.ciphertext,
                                    header_dh_public: ratchet_msg.header.dh_public,
                                    header_pn: ratchet_msg.header.pn,
                                    header_n: ratchet_msg.header.n,
                                },
                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(
                                    chrono::SecondsFormat::Millis,
                                    true,
                                )),
                            };
                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                let _ = crate::send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                        peer_id: peer_id_for_retry.clone(),
                                        msg: noid_msg,
                                    })
                                    .await;
                            }
                            // Row stays until MessageDelivered, not on queue.
                            let _ = sessions_for_retry
                                .save_session(&db, &peer_id_for_retry)
                                .await;
                        }
                        _ => log::warn!("Failed to encrypt pending message {}", message_id),
                    }
                }
            }
        }
    });
}

/// Regenerate our OTPK pool and republish the signed prekey bundle —
/// spawned when an initiator referenced a consumed prekey (MD-09) or the
/// pool runs low after a completed handshake (S1).
fn spawn_prekey_replenish(handle: &tauri::AppHandle) {
    let handle2 = handle.clone();
    tokio::spawn(async move {
        let app_state = handle2.state::<AppState>();
        let db = app_state.db.lock().await.clone();
        let Some(db) = db else { return };
        match app_state
            .ratchet_sessions
            .generate_and_store_prekeys(&db)
            .await
        {
            Ok(bundle) => {
                let my_id = app_state.my_id.lock().await.clone();
                if let Some(tx) = crate::p2p_sender(&app_state.p2p_tx) {
                    let _ = crate::send_p2p_cmd(
                        &tx,
                        crate::p2p::types::P2PCommand::PublishPrekeyBundle {
                            peer_id: my_id,
                            bundle,
                        },
                    )
                    .await;
                    log::info!("Republished prekey bundle — OTPK pool replenished");
                }
            }
            Err(e) => log::error!("Failed to regenerate prekey bundle: {}", e),
        }
    });
}
