//! P2P node supervisor — the login-gated spawn loop: waits for the gate,
//! unlocks key material, builds the node, spawns per-login tasks, drains
//! the event channel, backs off on unexpected death. Extracted from the
//! lib.rs setup (Q05/A5b); bodies moved verbatim, the six per-login spawns
//! now call `login_tasks::*` and the event match delegates to
//! `event_dispatch::dispatch_p2p_event`.

use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::p2p::{P2PEvent, P2PNode};
use crate::{safe_emit, AppState, P2PGate, MY_ID_WIPED};

pub(crate) async fn supervise_node(
    handle: tauri::AppHandle,
    app_data_dir_clone: std::path::PathBuf,
    my_id_state: Arc<Mutex<String>>,
    mut p2p_gate_rx: tokio::sync::watch::Receiver<P2PGate>,
) {
              // spawn → crash → respawn cycle; a stable run (>60s alive)
              // resets the backoff.
              let mut respawn_backoff = Duration::from_secs(1);
              // TI-11: a persistent failure otherwise spams p2p-error every
              // retry — emit the first failure and then every 6th attempt.
              let mut p2p_error_streak: u32 = 0;
              loop {
                // Wait for a successful login to open the gate.
                if p2p_gate_rx.wait_for(|g| g.open).await.is_err() {
                    log::error!("P2P start gate closed before login");
                    return;
                }
                // RC7: capture the gate seq for THIS incarnation — the
                // teardown watcher aborts us on ANY subsequent gate write
                // (incl. a coalesced wipe→relogin pair that ends open=true).
                let incarnation_seq = p2p_gate_rx.borrow().seq;
                let spawned_at = tokio::time::Instant::now();

                // A1: the active profile root — `cache/` in a decoy
                // session, the real data dir otherwise. Node keys, peer
                // cache, mailbox db and profile all live under it, so a
                // decoy incarnation never touches the real identity.
                let app_state = handle.state::<AppState>();
                let profile_dir = app_state.profile_dir();
                // Unlock node key material with the PIN-derived master key.
                // Legacy plaintext key files are migrated to the NOIDKEY1
                // envelope on first login after the upgrade.
                let master_key = {
                    let security = app_state.security.lock().await;
                    match security.get_master_key() {
                        Ok(k) => k,
                        Err(e) => {
                            log::error!("P2P start without master key: {}", e);
                            p2p_error_streak += 1;
                            if p2p_error_streak == 1 || p2p_error_streak.is_multiple_of(6) {
                                safe_emit(&handle, "p2p-error", "Master key unavailable");
                            }
                            // Do NOT return — that kills this task and P2P is
                            // gone until restart. Back off and retry; a fresh
                            // login (after KillPin wipe) re-enters cleanly.
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            continue;
                        }
                    }
                };

                let keys = (|| -> anyhow::Result<(libp2p::identity::Keypair, crate::security::DHTCipher, bool)> {
                    // Quarantine-and-regenerate semantics, same as the
                    // headless relay: a corrupt key file must not wedge the
                    // GUI node — it is moved aside and a fresh key minted.
                    let mut regenerated = false;
                    // SEC-1111-09: identity.key is strict — a GCM tag
                    // failure means tampering/wrong master, never a silent
                    // re-mint of the node identity.
                    let id_bytes = crate::security::key_store::load_or_regen_strict(
                        &profile_dir.join("identity.key"),
                        &master_key,
                        || {
                            libp2p::identity::Keypair::generate_ed25519()
                                .to_protobuf_encoding()
                                .map_err(|e| anyhow::anyhow!("keypair encode: {}", e))
                        },
                        |raw| libp2p::identity::Keypair::from_protobuf_encoding(raw).is_ok(),
                        &mut regenerated,
                    )?;
                    let local_key = libp2p::identity::Keypair::from_protobuf_encoding(&id_bytes)?;
                    let dht_bytes = crate::security::key_store::load_or_regen(
                        &profile_dir.join("dht.key"),
                        &master_key,
                        || Ok(crate::security::DHTCipher::new().private_key_bytes().to_vec()),
                        |raw| raw.len() == 32,
                        &mut regenerated,
                    )?;
                    let dht_cipher = crate::security::DHTCipher::from_private_bytes(&dht_bytes)
                        .map_err(|e| anyhow::anyhow!("dht key decode: {}", e))?;
                    Ok((local_key, dht_cipher, regenerated))
                })();

                let (local_key, dht_cipher, regenerated) = match keys {
                    Ok(k) => k,
                    Err(e) => {
                        log::error!("Failed to unlock node keys: {}", e);
                        p2p_error_streak += 1;
                        if p2p_error_streak == 1 || p2p_error_streak.is_multiple_of(6) {
                            safe_emit(&handle, "p2p-error", "Failed to unlock node keys");
                        }
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };
                if regenerated {
                    // identity.key was corrupt — we have a NEW PeerId, so old
                    // invites/contacts keyed to the previous id are stale.
                    log::warn!("Node identity regenerated after key corruption — PeerId changed");
                    safe_emit(&handle, "p2p-error", "Node identity was regenerated after key file corruption");
                }

                // Share the cipher with the command layer (mailbox envelopes).
                let dht_cipher_shared = match crate::security::DHTCipher::from_private_bytes(
                    &dht_cipher.private_key_bytes(),
                ) {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        log::error!("Failed to clone DHT cipher: {}", e);
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };
                match handle.state::<AppState>().dht_cipher.lock() {
                    Ok(mut g) => *g = Some(dht_cipher_shared),
                    Err(e) => log::error!("dht_cipher lock poisoned on startup: {}", e),
                }

                // Onion transport hookup: when a Tor generation is running
                // (consent+mode), the node's swarm gets a TorTransport.
                let tor_ref = handle.state::<AppState>().inner().tor.clone();
                match P2PNode::new_with_keys(&profile_dir, local_key, dht_cipher, master_key, Some(tor_ref)).await {
                    Err(e) => {
                        // Surface the real cause — the previous code dropped it,
                        // leaving a generic "P2P not initialized" in the UI while
                        // the gate stayed open and the loop retried instantly.
                        log::error!("Failed to create P2P node: {}", e);
                        p2p_error_streak += 1;
                        if p2p_error_streak == 1 || p2p_error_streak.is_multiple_of(6) {
                            safe_emit(&handle, "p2p-error", format!("Failed to initialize P2P node: {}", e));
                        }
                        // The login gate is still open — back off instead of
                        // hot-looping on a persistent failure (e.g. an
                        // unavailable socket on a restricted platform).
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                    Ok(mut node) => {
                    p2p_error_streak = 0;
                    let peer_id = node.peer_id.to_string();
                    *my_id_state.lock().await = peer_id.clone();
                    safe_emit(&handle, "my-id", peer_id);
                    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<P2PEvent>(100);
                    let (cmd_tx, cmd_rx) =
                        tokio::sync::mpsc::channel::<crate::p2p::P2PCommand>(100);

                    // send_replace (not send): the watch channel keeps no
                    // receiver alive — send() would fail and drop cmd_tx,
                    // instantly closing the node's command channel.
                    handle.state::<AppState>().p2p_tx.send_replace(Some(cmd_tx));

                    // SEC-1111-05: seed the contact set so identity
                    // announcements fan out only to confirmed contacts.
                    crate::push_contacts::push_contacts_to_node(handle.state::<AppState>().inner()).await;

                    // Mailbox storage uses the node's own mailbox.db
                    // (opened in P2PNode::with_config) — deliberately NOT the
                    // login-gated user DB, so this node can serve mailbox
                    // requests before login and as a headless relay.
                    // Phase J.2: Set audit log reference for DHT/replay logging
                    node.set_audit_log(handle.state::<AppState>().audit_log.clone());

                    log::debug!("P2P node started with peer_id: {}", node.peer_id);

                    // Phase 5.2: Re-enable public bootstrap for WAN connectivity.
                    // Public bootstrap.libp2p.io nodes provide DHT routing for WAN.
                    // mDNS remains for LAN discovery.
                    let bootstrap_nodes = crate::p2p::load_bootstrap_nodes(&app_data_dir_clone);
                    log::info!("Bootstrapping with {} public nodes for WAN", bootstrap_nodes.len());
                    if let Err(e) = node.bootstrap(bootstrap_nodes) {
                        log::warn!("Bootstrap failed (WAN may not work): {}", e);
                    }

                    // Warm start: dial peers remembered from last session so a
                    // returning node rejoins its circle without a new invite.
                    node.seed_from_peer_cache();

                    // Warm start: re-subscribe every persisted room topic and
                    // re-announce our profile — room keys live only in the
                    // node's memory, so without this rooms stay silent until
                    // manually opened.
                    let mut login_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
                    // RC4: per-login background tasks — all aborted on gate close
                    {
                        login_tasks.push(crate::login_tasks::spawn_warm_rejoin(&handle));
                        login_tasks.push(crate::login_tasks::spawn_maint_cleanup(&handle));
                    }

                    // Run node. RC8: the result was silently dropped — a
                    // persistent failure respawned with zero diagnostics.
                    let node_task = tokio::spawn(async move {
                        match node.run(event_tx, cmd_rx).await {
                            Ok(()) => log::info!("P2P node exited cleanly"),
                            Err(e) => log::error!("P2P node run failed: {:#}", e),
                        }
                    });

                    // Wipe watcher: when the login gate flips back to false
                    // (KillPin), aborting the node task drops its event sender,
                    // which ends the forwarding loop below and unwinds us back
                    // to the gate wait. The watcher owns the JoinHandle — the
                    // run task is never awaited anywhere else.

                    // Auto-publish username to DHT on startup
                        login_tasks.push(crate::login_tasks::spawn_username_publish(&handle));

                    // Periodic username republish to DHT (every 30 minutes)
                        login_tasks.push(crate::login_tasks::spawn_republish_loop(&handle));

                    // Online status is connection-fact driven:
                    // ConnectionEstablished → peer-online, ConnectionClosed →
                    // peer-offline. The old periodic Ping/Pong probes are gone —
                    // each one triggered a doomed dial per offline contact.
                    // Reconnection comes from the warm-start peer cache and
                    // inbound dials; outgoing sends self-gate via dial backoff.

                    // Phase H.1: Periodic mailbox retry — pending messages are
                    // routed to the recipient's mailbox node via DHT lookup.
                    // Per-peer exponential backoff: a peer that stays offline
                    // is looked up less and less often (60s → 10min cap).
                        login_tasks.push(crate::login_tasks::spawn_mailbox_retry(&handle));

                    // Phase I.1: Periodic mailbox retrieval — check our own mailbox.
                    // Interval comes from ConnectivityConfig.mailbox_poll_secs
                    // (default 300s — "Connections" settings page).
                        login_tasks.push(crate::login_tasks::spawn_mailbox_retrieve(&handle));

                    // RC4+RC7: one watcher aborts the node task AND every
                    // per-login background loop (republish, mailbox
                    // retry/retrieve, warm-start rejoin). The trigger is
                    // `seq != incarnation_seq || !open`: a plain `!open`
                    // watch would coalesce a fast wipe→relogin pair into
                    // invisibility and leave this node running on wiped keys.
                    {
                        let mut stop_rx = p2p_gate_rx.clone();
                        tokio::spawn(async move {
                            let _ = stop_rx
                                .wait_for(|g| !g.open || g.seq != incarnation_seq)
                                .await;
                            node_task.abort();
                            for h in &login_tasks { h.abort(); }
                            // SEC-A01: abort is a request, not a join —
                            // await each handle so quiescence is proven
                            // before the wipe reaches filesystem erase.
                            let _ = node_task.await;
                            for h in login_tasks { let _ = h.await; }
                        });
                    }

                    // Forward events to frontend
                    // Relay-status events fire on every connection/reservation
                    // churn — dedupe so identical snapshots don't spam the log
                    // and re-render the UI. Only a real change is emitted.
                    let mut last_relay_status: Option<crate::p2p::relay_status::RelayStatus> = None;
                    while let Some(event) = event_rx.recv().await {
                        crate::event_dispatch::dispatch_p2p_event(event, &handle, &mut last_relay_status).await;
                    }
                }
                }

                // Reached after the event channel closed — node task ended
                // (wipe abort) or never started. Reset all node-facing state
                // so a subsequent login builds a clean node.
                {
                    let app_state = handle.state::<AppState>();
                    let _ = app_state.p2p_tx.send_replace(None);
                    if let Ok(mut g) = app_state.dht_cipher.lock() { *g = None; }
                    *my_id_state.lock().await = MY_ID_WIPED.to_string();
                    // TI-20: the frontend still holds the dead peer id —
                    // re-emit so it can clear identity-dependent UI state.
                    safe_emit(&handle, "my-id", MY_ID_WIPED);
                    app_state.ratchet_sessions.clear_all().await;
                    app_state.undecrypted_inbound.lock().await.clear();
                    app_state.mailbox_decrypt_attempts.lock().await.clear();
                    app_state.mailbox_seen_hashes.lock().await.clear();
                    // RC12: teardown was incomplete — the UI kept reading a
                    // stale relay snapshot and the connected-peer set from
                    // the dead incarnation.
                    *app_state.relay_status.lock().await =
                        crate::p2p::RelayStatus::default();
                    app_state.connected_peers.lock().await.clear();
                    // A1: session ended — the next login resolves its own
                    // profile root (real or decoy).
                    app_state
                        .is_decoy
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
                // RC8: if the node died while the gate was still open
                // (crash, forwarder failure — NOT a wipe), back off before
                // respawning; a persistent failure otherwise hot-loops the
                // whole spawn → die → respawn cycle. A healthy run (>60s)
                // resets the backoff.
                if p2p_gate_rx.borrow().open {
                    if spawned_at.elapsed() > Duration::from_secs(60) {
                        respawn_backoff = Duration::from_secs(1);
                    }
                    log::warn!(
                        "P2P node died while gate open — respawning in {:?}",
                        respawn_backoff
                    );
                    // TI-11: tell the UI the incarnation died — ratchet
                    // sessions and peer state were just reset, so a
                    // "reconnecting" indicator is honest, not noise.
                    safe_emit(&handle, "p2p-restarting", serde_json::json!({
                        "retry_in_secs": respawn_backoff.as_secs()
                    }));
                    tokio::time::sleep(respawn_backoff).await;
                    respawn_backoff =
                        (respawn_backoff * 2).min(Duration::from_secs(60));
                }
                log::info!("P2P node torn down — awaiting next login");
              }
}

/// Live Tor status → UI: forwards every supervisor snapshot as a
/// `tor-status` event, enriched with the persisted relay flags from the
/// config file (the supervisor doesn't carry them).
pub(crate) fn spawn_tor_status_fwd(handle: tauri::AppHandle, cfg_path: std::path::PathBuf) {
    tauri::async_runtime::spawn(async move {
        let mut rx = handle.state::<AppState>().inner().tor.status_watch();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let mut s = rx.borrow().clone();
            if let Ok(cfg) = crate::p2p::tor::config::load(&cfg_path) {
                s.relay_enabled = cfg.onion_relay_enabled;
                s.allow_metered_relay = cfg.allow_metered_relay;
            }
            safe_emit(&handle, "tor-status", s);
        }
    });
}
