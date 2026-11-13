use std::collections::HashMap;
use std::sync::Arc;
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;

mod app_state;
mod auth;
mod android_bridge;
mod commands;
mod contact_dispatch;
mod decrypt_mailbox_envelope;
mod dispatch_mailbox_plaintext;
mod encrypt_mailbox_ecdh;
mod ev_dht;
mod ev_mailbox;
mod ev_peer;
mod ev_room;
mod event_dispatch;
mod file_inbox;
mod inbound_retry;
mod login_tasks;
mod node_supervisor;
mod pending_codec;
mod pending_flush;
mod persist_initiated_session;
mod process_mailbox_item;
mod push_contacts;
mod request_dispatch;
mod serialize_ratchet_chat;
mod x3dh_dispatch;
mod validation;
pub mod db;
pub mod log_redact;
pub mod p2p;
pub mod relay_headless;
pub mod room_control;
pub mod room_presence;
pub mod room_rekey;
pub mod security;
pub mod util;
#[cfg(desktop)]
mod tray;

#[cfg(test)]
mod auth_test;
#[cfg(test)]
mod log_redact_test;
#[cfg(test)]
mod persist_initiated_session_test;

use security::SecurityManager;

pub use app_state::*;
pub use inbound_retry::retry_undecrypted_messages;
pub use pending_codec::*;

/// Safe emit helper — logs failure instead of panicking.
/// A failed UI event must never terminate the event-forwarding task or P2P loop.
pub(crate) fn safe_emit<S: serde::Serialize + Clone>(handle: &tauri::AppHandle, event: &str, payload: S) {
    if let Err(e) = handle.emit(event, payload) {
        log::warn!("Failed to emit event '{}': {}", event, e);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // TI-13: shared flag so the close handler knows whether a tray icon
    // (and therefore a Quit menu) actually exists.
    #[cfg(desktop)]
    let tray_available = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(desktop)]
    let tray_flag_for_close = tray_available.clone();
    let builder = tauri::Builder::default();
    // TI-21: single_instance must be the FIRST plugin — a second launch
    // should hand off to the existing window and exit before any other
    // plugin or setup code runs (two nodes would fight over the same
    // PeerId, DB and listen ports).
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    let builder = builder
        .plugin(
            tauri_plugin_log::Builder::new()
                // Keep dependency debug/SQL traces out of diagnostic logs.
                .level(log::LevelFilter::Info)
                .level_for("noid_lib",
                    std::env::var("NOID_LOG")
                        .ok()
                        .and_then(|s| s.parse::<log::LevelFilter>().ok())
                        .unwrap_or(log::LevelFilter::Info),
                )
                .level_for("sqlx", log::LevelFilter::Warn)
                // B6: default log name is the crate name — "noid_lib.log" —
                // which confuses log collection/support tooling. Name the
                // file after the product instead.
                .targets([
                    tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout),
                    tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir {
                        file_name: Some("noid".to_string()),
                    }),
                ])
                .max_file_size(2_000_000)
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepSome(2))
                // Privacy: strip IPs and shorten PeerIds in every log line.
                .format(|out, _message, record| {
                    out.finish(format_args!(
                        "{} {}",
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        crate::log_redact::format_record(record)
                    ))
                })
                .build(),
        )
        .setup(move |app| {
            // SEC-1111-10: screen-capture exclusion from window start —
            // WDA_EXCLUDEFROMCAPTURE (Windows) / NSWindowSharingNone
            // (macOS) so chats and the PIN screen never leak into OS
            // screenshots, screen recorders or Alt-Tab previews.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_content_protected(true);
            }
            // RUN-A09: never fall back to "." — KillPin recursively deletes
            // this root, so an unresolved app-data dir would aim the wipe at
            // the process working directory. Fail startup instead.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!(
                        "app data dir resolution failed ({}); refusing to start with an ambiguous wipe root",
                        e
                    )
                    .into()
                })?;
            if !app_data_dir.is_absolute() || app_data_dir.parent().is_none() {
                return Err(format!(
                    "app data dir {:?} is not an owned absolute path — refusing to start",
                    app_data_dir
                )
                .into());
            }
            if !app_data_dir.exists() {
                if let Err(e) = std::fs::create_dir_all(&app_data_dir) {
                    log::error!("Failed to create app data dir: {}", e);
                }
            }

            // audit.log lives INSIDE app_data_dir so KillPin's wipe covers it —
            // it records security events (logins, replays, kill-pin) that must
            // not survive a wipe.
            let app_log_dir = app
                .path()
                .app_log_dir()
                .unwrap_or_else(|_| app_data_dir.clone());

            let (p2p_start_tx, p2p_start_rx) =
                tokio::sync::watch::channel(P2PGate { open: false, seq: 0 });
            let (p2p_tx, _p2p_rx) = tokio::sync::watch::channel(None);
            let state = AppState {
                security: Arc::new(Mutex::new(SecurityManager::new(app_data_dir.clone()))),
                db: Arc::new(Mutex::new(None)),
                p2p_tx,
                my_id: Arc::new(Mutex::new(MY_ID_PENDING.into())),
                app_data_dir: app_data_dir.clone(),
                auth_manager: Arc::new(Mutex::new(auth::AuthManager::load(&app_data_dir))),
                ratchet_sessions: Arc::new(crate::security::RatchetSessionManager::new()),
                audit_log: Arc::new(crate::security::audit_log::AuditLog::new(&app_data_dir)),
                relay_status: Arc::new(Mutex::new(crate::p2p::RelayStatus::default())),
                relay_config: Arc::new(Mutex::new(crate::p2p::RelayConfig::load(&app_data_dir))),
                connectivity_config: Arc::new(Mutex::new(
                    crate::p2p::connectivity_config::ConnectivityConfig::load(&app_data_dir),
                )),
                undecrypted_inbound: Arc::new(Mutex::new(std::collections::HashMap::new())),
                session_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
                inbound_peer_locks: Arc::new(Mutex::new(std::collections::HashMap::new())),
                pending_flush_cooldown: Arc::new(Mutex::new(std::collections::HashMap::new())),
                mailbox_decrypt_attempts: Arc::new(Mutex::new(
                    std::collections::HashMap::new(),
                )),
                mailbox_seen_hashes: Arc::new(Mutex::new(
                    std::collections::HashSet::new(),
                )),
                dht_cipher: std::sync::Mutex::new(None),
                p2p_start_tx,
                login_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                network_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                app_log_dir,
                connected_peers: Arc::new(Mutex::new(std::collections::HashSet::new())),
                invite_rv: Arc::new(Mutex::new(None)),
                file_inbox: Arc::new(Mutex::new(HashMap::new())),
                pending_file_offers: Arc::new(Mutex::new(HashMap::new())),
                tor: crate::p2p::tor::handle::TorHandle::new(app_data_dir.join("tor")),
                is_decoy: std::sync::atomic::AtomicBool::new(false),
            };

            app.manage(state);

            // A6/A3: Android ConnectivityManager / WorkManager wake tokens
            // arrive through a JNI channel — drain it and forward each as
            // NetworkChanged so the node drops stale addrs and re-reserves
            // relays. On other platforms the channel simply never fires.
            {
                let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
                android_bridge::register_network_tx(net_tx);
                let net_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    while net_rx.recv().await.is_some() {
                        let app_state = net_handle.state::<AppState>();
                        if let Some(tx) = app_state.p2p() {
                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::NetworkChanged).await;
                        }
                    }
                });
            }

            // Tray icon (desktop only): the window's close button hides to
            // tray (see on_window_event below) — Quit lives in the tray menu.
            #[cfg(desktop)]
            {
                match tray::setup_tray(app) {
                    Ok(()) => tray_available.store(true, std::sync::atomic::Ordering::Relaxed),
                    Err(e) => {
                        // TI-13: on Linux/GNOME without a tray there is no
                        // Quit menu — leave the flag false so CloseRequested
                        // exits normally instead of hiding the window into a
                        // void the user can never reopen.
                        log::warn!("Failed to set up tray icon: {}", e);
                    }
                }
            }

            // Spawn P2P background thread — GATED on login. The node (and
            // therefore every listener, mailbox service and DHT record) does
            // not exist until a successful login unlocks the key store.
            let handle = app.handle().clone();
            let my_id_state = handle.state::<AppState>().my_id.clone();
            let app_data_dir_clone = app_data_dir.clone();
            let p2p_gate_rx = p2p_start_rx;

            // Live Tor status → UI: forward every supervisor snapshot as a
            // `tor-status` event so settings/main-screen indicators update
            // without polling. The snapshot is enriched with the persisted
            // relay flags (the supervisor doesn't carry them — the config
            // file does), so toggle state stays consistent everywhere.
            crate::node_supervisor::spawn_tor_status_fwd(
                app.handle().clone(),
                app_data_dir.join("tor").join("tor_config.json"),
            );
            // tauri::async_runtime::spawn — setup() runs on the main
            // thread with NO ambient Tokio runtime (tokio::spawn panics
            // there — crashes Android on startup).
            tauri::async_runtime::spawn(async move {
                crate::node_supervisor::supervise_node(
                    handle,
                    app_data_dir_clone,
                    my_id_state,
                    p2p_gate_rx,
                )
                .await;
            });

            Ok(())
        });

    // Desktop-only: close button hides to tray instead of quitting — the
    // P2P node keeps running in the background. Real exit: tray menu → Quit.
    #[cfg(desktop)]
    let builder = builder
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // TI-13: without a tray there is no way back or out —
                // allow the normal close/exit instead of hiding.
                if tray_flag_for_close.load(std::sync::atomic::Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        });

    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            commands::login,
            commands::setup_pins,
            commands::kill_switch,
            commands::lock_now::lock_now,
            commands::is_first_run,
            commands::is_kill_pin_configured,
            commands::validate_peer_id,
            commands::remove_contact,
            commands::delete_chat,
            commands::get_chat_messages,
            commands::get_new_messages_since,
            commands::get_all_missed_messages,
            commands::get_last_sync_time,
            commands::update_last_sync_time,
            commands::reconnect_to_contacts,
            commands::register_folder,
            commands::invite_to_room,
            commands::accept_room_invite,
            commands::decline_room_invite,
            commands::list_pending_room_invites,
            commands::send_chat_message,
            commands::get_profile,
            commands::update_profile,
            commands::get_my_id,
            commands::get_network_snapshot,
            commands::get_pending_message_ids,
            commands::get_unread_counts::get_unread_counts,
            commands::set_unread_count::set_unread_count,
            commands::get_relay_status,
            commands::get_tor_status,
            commands::set_tor_mode,
            commands::rotate_onion_identity,
            commands::get_connectivity_config,
            commands::set_connectivity_config,
            commands::set_decoy_pin::set_decoy_pin,
            commands::is_decoy_configured::is_decoy_configured,
            commands::set_tor_relay,
            commands::set_tor_bridges::set_tor_bridges,
            commands::set_tor_bridges::get_tor_bridges,
            commands::get_relay_config,
            commands::get_reachability,
            commands::get_proxy_config,
            commands::set_proxy_config,
            commands::test_proxy,
            commands::set_node_role,
            commands::set_hop_relays,
            commands::set_privacy_mode,
            commands::send_contact_request,
            commands::connect_to_addr,
            commands::get_my_invite,
            commands::accept_contact_request,
            commands::deny_contact_request,
            commands::get_contacts,
            commands::get_contact_requests,
            commands::send_read_receipt,
            commands::set_cover_traffic,
            commands::send_typing_indicator,
            commands::enable_screenshot_protection,
            commands::disable_screenshot_protection,
            commands::join_room,
            commands::create_room,
            commands::list_rooms,
            commands::get_room_messages,
            commands::send_room_message,
            commands::get_room_info,
            commands::rename_room,
            commands::set_room_avatar,
            commands::remove_room_member,
            commands::leave_room,
            commands::delete_room,
            commands::send_file_offer,
            commands::send_file_chunk,
            commands::accept_file_offer,
            commands::decline_file_offer,
            commands::get_shared_folders,
            commands::approve_room_member,
            commands::update_folder_path,
            commands::update_folder_visibility,
            commands::update_folder_password,
            commands::delete_shared_folder,
            commands::search_shared_folders,
            commands::set_username,
            commands::check_username,
            commands::lookup_user,
            commands::lookup_by_peer_id,
            commands::get_username
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|handle, event| {
            // RC9: graceful shutdown — the node used to die instantly on
            // exit (in-flight requests torn, peer cache unflushed). Send
            // Shutdown so it persists peers and drops the swarm cleanly,
            // then close the gate so per-login loops abort. The brief
            // sleep gives the node task a window to flush before the
            // runtime tears down.
            if matches!(event, tauri::RunEvent::Exit) {
                let state = handle.state::<AppState>();
                if let Some(tx) = state.p2p() {
                    let _ = tx.try_send(crate::p2p::P2PCommand::Shutdown);
                }
                gate_set(&state.p2p_start_tx, false);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });
}
