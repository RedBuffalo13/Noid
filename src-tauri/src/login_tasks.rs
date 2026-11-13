//! Per-login background tasks — warm-start room rejoin, DB maintenance,
//! username publish/republish, mailbox retry/retrieve. Extracted from the
//! lib.rs supervisor (Q05/A5b); bodies moved verbatim, only the spawn
//! wrapper was lifted into a named fn per task.

use tauri::Manager;
use tokio::time::{interval, Duration};

use crate::{safe_emit, send_p2p_cmd, AppState};

/// Warm start: re-subscribe every persisted room topic, self-assign legacy
/// ownerless rooms, re-announce our profile.
pub(crate) fn spawn_warm_rejoin(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let rejoin_handle = handle.clone();
    tokio::spawn(async move {
                            let app_state = rejoin_handle.state::<AppState>();
                            let keys = {
                                let db_state = app_state.db.lock().await;
                                match db_state.as_ref() {
                                    Some(db) => {
                                        let mut out = Vec::new();
                                        if let Ok(rooms) = db.list_rooms().await {
                                            for (id, _) in rooms {
                                                if let Ok(Some(k)) = db.get_room_key(&id).await {
                                                    out.push((id, k));
                                                }
                                            }
                                        }
                                        out
                                    }
                                    None => Vec::new(),
                                }
                            };
                            if let Some(tx) = app_state.p2p() {
                                for (room_id, key) in keys {
                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::JoinRoom {
                                            room_id,
                                            room_key: Some(key),
                                        })
                                        .await;
                                }
                            }
                            // Legacy ownerless rooms: rooms we created
                            // before owner tracking have no owner and we
                            // are absent from their member list → self-
                            // assign and tell the members via Meta{owner}
                            // so their records converge (pending/mailbox
                            // reaches offline peers on reconnect).
                            {
                                let my_id = app_state.my_id.lock().await.clone();
                                let assigned = {
                                    let db_state = app_state.db.lock().await;
                                    match db_state.as_ref() {
                                        Some(db) => db
                                            .backfill_room_owners(&my_id)
                                            .await
                                            .unwrap_or_default(),
                                        None => Vec::new(),
                                    }
                                };
                                for room_id in assigned {
                                    let members = {
                                        let db_state = app_state.db.lock().await;
                                        match db_state.as_ref() {
                                            Some(db) => db
                                                .get_room_members(&room_id)
                                                .await
                                                .unwrap_or_default(),
                                            None => Vec::new(),
                                        }
                                    };
                                    for m in members.into_iter().filter(|m| m.approved) {
                                        let _ = crate::room_control::send_room_control(
                                            &rejoin_handle,
                                            &room_id,
                                            &m.peer_id,
                                            &crate::p2p::RoomControlPayload::Meta {
                                                name: None,
                                                avatar: None,
                                                owner: Some(my_id.clone()),
                                            },
                                        )
                                        .await;
                                    }
                                }
                            }
                            crate::room_presence::announce_all_rooms(&rejoin_handle).await;
    })
}

/// DB maintenance once per login (DB11 orphan messages, DB24 contact-request
/// TTL/cap, DB25 orphan ratchet states).
pub(crate) fn spawn_maint_cleanup(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let maint_handle = handle.clone();
    tokio::spawn(async move {
                            let app_state = maint_handle.state::<AppState>();
                            let db = app_state.db.lock().await.clone();
                            let my_id = app_state.my_id.lock().await.clone();
                            if let Some(db) = db {
                                if let Err(e) = db.maintenance_cleanup(&my_id).await {
                                    log::warn!("maintenance_cleanup failed: {}", e);
                                }
                            }
    })
}

/// Auto-publish our profile/username to the DHT on login.
pub(crate) fn spawn_username_publish(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let publish_handle = handle.clone();
    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(5)).await;

                        let app_state = publish_handle.state::<AppState>();
                        let db = app_state.db.lock().await.clone();
                        if let Some(db) = db {
                            if let Ok(Some(username)) = db.get_username().await {
                                let my_id = app_state.my_id.lock().await.clone();
                                let (nickname, avatar) = match db.get_profile().await {
                                    Ok((n, a)) => (n, a),
                                    Err(_) => (username.clone(), None),
                                };

                                let short_id: String = my_id[my_id.len() - 4..].to_string();
                                let record = crate::p2p::DHTUserRecord {
                                    peer_id: my_id,
                                    username: username.clone(),
                                    nickname,
                                    avatar,
                                    short_id,
                                    updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                                    signature: None,
            revoked: false,
                                };

                                if let Some(tx) = app_state.p2p() {
                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::PublishUsername {
                                        username: username.clone(),
                                        record,
                                    }).await;
                                    log::debug!("Auto-published username '{}' to DHT on startup", username);
                                }
                            } else {
                                log::debug!("No username to auto-publish on startup");
                            }
                        }
    })
}

/// Periodic username republish to DHT (every 30 minutes).
pub(crate) fn spawn_republish_loop(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let republish_handle = handle.clone();
    tokio::spawn(async move {
                        let mut republish_interval = interval(Duration::from_secs(1800));
                        loop {
                            republish_interval.tick().await;

                            let app_state = republish_handle.state::<AppState>();
                            let db = app_state.db.lock().await.clone();
                            if let Some(db) = db {
                                if let Ok(Some(username)) = db.get_username().await {
                                    let my_id = app_state.my_id.lock().await.clone();
                                    let (nickname, avatar) = match db.get_profile().await {
                                        Ok((n, a)) => (n, a),
                                        Err(_) => (username.clone(), None),
                                    };

                                    let short_id: String = my_id[my_id.len() - 4..].to_string();
                                    let record = crate::p2p::DHTUserRecord {
                                        peer_id: my_id,
                                        username: username.clone(),
                                        nickname,
                                        avatar,
                                        short_id,
                                        updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                                        signature: None,
            revoked: false,
                                    };

                                    if let Some(tx) = app_state.p2p() {
                                        let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::PublishUsername {
                                            username: username.clone(),
                                            record,
                                        }).await;
                                        log::debug!("Periodic republish: username '{}' re-published to DHT", username);
                                    }
                                }

                                // D16: the prekey bundle was published once at
                                // login — remote holders clamp TTL to ~48h, so
                                // a node alive >2d silently vanished from X3DH
                                // resolution. Rebuild the bundle (tops the
                                // OTPK pool back to 10) and re-publish.
                                match app_state.ratchet_sessions
                                    .generate_and_store_prekeys(&db)
                                    .await
                                {
                                    Ok(bundle) => {
                                        let my_id = app_state.my_id.lock().await.clone();
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::PublishPrekeyBundle {
                                                peer_id: my_id,
                                                bundle,
                                            }).await;
                                            log::debug!("Periodic republish: prekey bundle re-published to DHT");
                                        }
                                    }
                                    Err(e) => log::warn!("Periodic prekey republish failed: {}", e),
                                }
                            }
                        }
    })
}

/// Periodic mailbox retry — pending messages are routed to the recipient's
/// mailbox node via DHT lookup with per-peer exponential backoff.
pub(crate) fn spawn_mailbox_retry(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let mailbox_retry_handle = handle.clone();
    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(30)).await; // Start after 30s
                        let mut interval = interval(Duration::from_secs(15));
                        let mut retry_at: std::collections::HashMap<String, (u32, std::time::Instant)> =
                            std::collections::HashMap::new();
                        // Per-peer flush cooldown: each flush resends the whole
                        // pending queue, and rows stay pending until the remote
                        // durably acks — without a cooldown a flapping conn
                        // gets the full queue re-requested every 15s tick,
                        // amplifying the failure storm into a flood.
                        let mut flushed_at: std::collections::HashMap<String, std::time::Instant> =
                            std::collections::HashMap::new();
                        loop {
                            interval.tick().await;
                            let app_state = mailbox_retry_handle.state::<AppState>();
                            let db_state = app_state.db.lock().await;
                            if let Some(db) = db_state.as_ref() {
                                // F14: expire pending rows older than the
                                // mailbox TTL (7d) — they can never land.
                                if let Ok(expired) = db.cleanup_stale_pending(7 * 24 * 3600).await {
                                    for (peer_id, message_id) in expired {
                                        log::warn!("Pending message {} to {} expired — dropped", message_id, peer_id);
                                        safe_emit(&mailbox_retry_handle, "message-failed", serde_json::json!({
                                            "to": peer_id,
                                            "error": "delivery expired",
                                        }));
                                    }
                                }
                                // Get all peers with pending messages
                                if let Ok(pending) = db.get_pending_messages_all().await {
                                    // Group by peer_id — only lookup each peer once
                                    let mut peers_to_check: std::collections::HashSet<String> = std::collections::HashSet::new();
                                    for (_row_id, _content, _msg_id, peer_id) in &pending {
                                        peers_to_check.insert(peer_id.clone());
                                    }
                                    drop(db_state);
                                    let now = std::time::Instant::now();
                                    if let Some(tx) = app_state.p2p() {
                                        for peer_id in &peers_to_check {
                                            // F11: a live conn flushes pending
                                            // directly — no mailbox lookup needed.
                                            if app_state
                                                .connected_peers.lock().await
                                                .contains(peer_id)
                                            {
                                                let recent = flushed_at
                                                    .get(peer_id)
                                                    .map(|t| t.elapsed() < Duration::from_secs(30))
                                                    .unwrap_or(false);
                                                if !recent {
                                                    flushed_at
                                                        .insert(peer_id.clone(), std::time::Instant::now());
                                                    let h = mailbox_retry_handle.clone();
                                                    let p = peer_id.clone();
                                                    crate::track_task(&mailbox_retry_handle, tokio::spawn(async move {
                                                        crate::pending_flush::flush_pending_for_peer(&h, &p).await;
                                                    })).await;
                                                }
                                                continue;
                                            }
                                            let (attempts, next) =
                                                retry_at.get(peer_id).copied().unwrap_or((0, now));
                                            if next > now {
                                                continue;
                                            }
                                            let delay = std::time::Duration::from_secs(
                                                60u64.saturating_mul(1u64 << attempts.min(4)).min(600),
                                            );
                                            retry_at.insert(
                                                peer_id.clone(),
                                                (attempts + 1, now + delay),
                                            );
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                                peer_id: peer_id.clone(),
                                            }).await;
                                        }
                                    }
                                    // Drop backoff state for peers whose queue
                                    // emptied — next pending row starts fresh.
                                    retry_at.retain(|p, _| peers_to_check.contains(p));
                                    flushed_at.retain(|p, _| peers_to_check.contains(p));
                                } else {
                                    drop(db_state);
                                }
                            } else {
                                drop(db_state);
                            }
                        }
    })
}

/// Periodic mailbox retrieval — check our own mailbox (interval from
/// ConnectivityConfig.mailbox_poll_secs).
pub(crate) fn spawn_mailbox_retrieve(handle: &tauri::AppHandle) -> tokio::task::JoinHandle<()> {
    let mailbox_retrieve_handle = handle.clone();
    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(10)).await; // Start after bootstrap
                        let poll_secs = {
                            let app_state = mailbox_retrieve_handle.state::<AppState>();
                            let secs = app_state.connectivity_config.lock().await.mailbox_poll_secs;
                            secs
                        };
                        let mut interval = interval(Duration::from_secs(poll_secs));
                        loop {
                            interval.tick().await;
                            let app_state = mailbox_retrieve_handle.state::<AppState>();
                            if let Some(my_id) = app_state.current_peer_id().await {
                                if let Some(tx) = app_state.p2p() {
                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                        peer_id: my_id.clone(),
                                    }).await;
                                    log::debug!("Periodic mailbox retrieval check for self");
                                }
                            }
                        }
    })
}
