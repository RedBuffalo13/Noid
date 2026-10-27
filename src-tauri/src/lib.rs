use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

mod auth;
mod android_bridge;
mod commands;
mod contact_dispatch;
mod file_inbox;
mod pending_flush;
mod persist_initiated_session;
mod request_dispatch;
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

use db::Database;
use p2p::{P2PEvent, P2PNode};
use security::SecurityManager;

/// Safe emit helper — logs failure instead of panicking.
/// A failed UI event must never terminate the event-forwarding task or P2P loop.
pub(crate) fn safe_emit<S: serde::Serialize + Clone>(handle: &tauri::AppHandle, event: &str, payload: S) {
    if let Err(e) = handle.emit(event, payload) {
        log::warn!("Failed to emit event '{}': {}", event, e);
    }
}

/// Retry buffered inbound ratchet messages once the DB and sessions are
/// available (called after login and after any successful ratchet decrypt).
/// Without this, offline redelivery that arrives before login is lost —
/// the sender deletes its pending copy after the send succeeds.
pub(crate) async fn retry_undecrypted_messages(handle: &tauri::AppHandle) {
    let app_state = handle.state::<AppState>();

    let buffered: Vec<(String, Vec<BufferedInbound>)> = {
        let mut buf = app_state.undecrypted_inbound.lock().await;
        if buf.is_empty() {
            return;
        }
        std::mem::take(&mut *buf).into_iter().collect()
    };

    // RC2: snapshot the Database — the global db guard must not be held
    // across `security`/`my_id`/`undecrypted_inbound` locks below.
    let db = match app_state.db.lock().await.clone() {
        Some(db) => db,
        None => {
            // DB still unavailable — put the messages back for a later retry.
            let mut buf = app_state.undecrypted_inbound.lock().await;
            for (peer, msgs) in buffered {
                buf.entry(peer).or_default().extend(msgs);
            }
            return;
        }
    };

    for (from, msgs) in buffered {
        if !app_state.ratchet_sessions.has_session(&from).await {
            let _ = app_state.ratchet_sessions.load_session(&db, &from).await;
        }
        for m in msgs {
            match app_state.ratchet_sessions.decrypt(&from, &m.msg).await {
                Ok(plaintext) => {
                    if db.message_exists(&m.id).await.unwrap_or(false) {
                        continue;
                    }
                    let text = String::from_utf8_lossy(&plaintext).to_string();
                    let my_id = app_state.my_id.lock().await.clone();
                    let ts = m.timestamp.clone().unwrap_or_else(|| {
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    });
                    // DB28/F20: emit only after a durable insert — a failed
                    // persist used to show a phantom message that vanished on
                    // restart.
                    let persisted = {
                        let security_guard = app_state.security.lock().await;
                        match security_guard.encrypt(&plaintext) {
                            Ok(enc) => db
                                .add_message_with_timestamp(&m.id, &from, &my_id, &enc, &ts)
                                .await
                                .map(|_| true)
                                .unwrap_or(false),
                            Err(e) => {
                                log::error!("Cannot encrypt buffered message {} for storage: {}", m.id, e);
                                false
                            }
                        }
                    };
                    let _ = app_state.ratchet_sessions.save_session(&db, &from).await;
                    if persisted {
                        log::debug!("Delivered buffered ratchet message {} from {}", m.id, from);
                        safe_emit(handle, "chat-msg", serde_json::json!({
                            "from": &from,
                            "data": {
                                "content": &text,
                                "id": &m.id,
                                "sender": &from,
                                "timestamp": &ts,
                            },
                        }));
                    } else {
                        log::warn!("Buffered message {} not persisted — not emitted", m.id);
                    }
                }
                Err(e) => {
                    log::warn!("Buffered message {} from {} still undecryptable: {}", m.id, from, e);
                    // The session may still arrive later via X3DH — re-buffer.
                    // RC24: honor the same 500-entry cap as the inbound
                    // buffer — a permanently undecryptable flood must not
                    // grow memory without bound.
                    let mut buf = app_state.undecrypted_inbound.lock().await;
                    let total: usize = buf.values().map(|v| v.len()).sum();
                    if total < 500 {
                        buf.entry(from.clone()).or_default().push(m);
                    }
                }
            }
        }
    }
}

/// Decrypt a `pending_messages.content` cell: "enc2:" (or legacy "enc1:")
/// + base64(AES-GCM blob). Rows without the prefix are legacy plaintext and
///   are returned as-is (they are migrated on write, not on read).
async fn decode_pending_content(
    security: &Arc<Mutex<SecurityManager>>,
    raw: &str,
) -> Option<String> {
    if let Some(b64) = raw
        .strip_prefix("enc2:")
        .or_else(|| raw.strip_prefix("enc1:"))
    {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let plaintext = security.lock().await.decrypt(&bytes).ok()?;
        Some(String::from_utf8_lossy(&plaintext).to_string())
    } else {
        // DB30: fail-open for legacy pre-encryption rows — flagged so the
        // surviving plaintext is visible in the log; writes are always
        // encrypted so this branch only shrinks over time.
        log::warn!("pending row carries legacy plaintext (pre-enc2 era) — passing through");
        Some(raw.to_string())
    }
}

/// Encrypt a pending body for storage — returns None when the master key is
/// not available; callers must then keep the message out of pending rather
/// than persist plaintext.
/// F13: pending-first for typed messages — the encrypted NOIDMSG1 row is
/// written BEFORE the send is queued, so a crash between enqueue and
/// OutboundFailure cannot lose a ContactRequest/RoomInvite/etc.
/// No-op when a row for this (peer, message_id) already exists.
pub(crate) async fn pend_typed_message(
    state: &tauri::State<'_, AppState>,
    peer_id: &str,
    msg: &crate::p2p::NoidMessage,
) {
    let db = state.db.lock().await.clone();
    let Some(db) = db else { return };
    if db
        .pending_exists_by_message_id(peer_id, &msg.id)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let json = match serde_json::to_string(msg) {
        Ok(j) => j,
        Err(_) => return,
    };
    if let Some(enc) = encode_pending_content(&state.security, &format!("NOIDMSG1:{}", json)).await {
        let _ = db
            .add_pending_message_with_content(peer_id, &enc, &msg.id)
            .await;
    }
}

/// AppHandle variant for non-command call sites (room_control, dispatchers).
pub(crate) async fn pend_typed_message_h(
    handle: &tauri::AppHandle,
    peer_id: &str,
    msg: &crate::p2p::NoidMessage,
) {
    let app_state = handle.state::<AppState>();
    let db = app_state.db.lock().await.clone();
    let Some(db) = db else { return };
    if db
        .pending_exists_by_message_id(peer_id, &msg.id)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let json = match serde_json::to_string(msg) {
        Ok(j) => j,
        Err(_) => return,
    };
    if let Some(enc) = encode_pending_content(&app_state.security, &format!("NOIDMSG1:{}", json)).await {
        let _ = db
            .add_pending_message_with_content(peer_id, &enc, &msg.id)
            .await;
    }
}

async fn encode_pending_content(
    security: &Arc<Mutex<SecurityManager>>,
    plaintext: &str,
) -> Option<String> {
    let enc = security.lock().await.encrypt(plaintext.as_bytes()).ok()?;
    Some(format!(
        "enc2:{}",
        base64::engine::general_purpose::STANDARD.encode(&enc)
    ))
}

pub struct AppState {
    pub security: Arc<Mutex<SecurityManager>>,
    pub db: Arc<Mutex<Option<Database>>>,
    /// Phase 1.1/5: watch channel holding the node's command sender.
    /// Lock-free reads (`borrow().clone()`), and — unlike OnceLock — it can be
    /// reset to `None` on KillPin wipe so a subsequent login starts a fresh node.
    pub p2p_tx: tokio::sync::watch::Sender<Option<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>>>,
    pub my_id: Arc<Mutex<String>>,
    pub app_data_dir: PathBuf,
    pub auth_manager: Arc<Mutex<auth::AuthManager>>,
    /// Phase 3.5: E2EE session manager (X3DH + Double Ratchet)
    pub ratchet_sessions: Arc<crate::security::RatchetSessionManager>,
    /// Phase E: Audit log for security-sensitive events
    pub audit_log: Arc<crate::security::audit_log::AuditLog>,
    /// Latest relay/NAT status snapshot (for UI queries).
    pub relay_status: Arc<Mutex<crate::p2p::RelayStatus>>,
    /// Persisted relay configuration (role, privacy, limits).
    pub relay_config: Arc<Mutex<crate::p2p::RelayConfig>>,
    /// Inbound ratchet messages that arrived before their session was usable
    /// (offline redelivery before login unlocks the DB). Retried post-login.
    pub undecrypted_inbound: Arc<Mutex<std::collections::HashMap<String, Vec<BufferedInbound>>>>,
    /// CR-03: per-peer FIFO for inbound request handling — each
    /// RequestReceived spawns a task, and an X3DHInit task awaiting a SQLite
    /// read was overtaken by the RatchetChat right behind it (decrypt failed
    /// "no session", message re-pended, next flush repeated). Peers stay
    /// parallel with each other; only same-peer requests serialize.
    pub inbound_peer_locks:
        Arc<Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// MD-08: last pending-flush timestamp per peer — PeerConnected and the
    /// retry tick used to double-fire a full resend within seconds.
    pub pending_flush_cooldown:
        Arc<Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// Failed-decrypt attempts per mailbox message id — a ciphertext from a
    /// pre-resync ratchet state can NEVER decrypt again; without a cap it is
    /// re-fetched and re-failed on every mailbox poll forever, re-arming the
    /// desync counter and churning pointless re-handshakes.
    pub mailbox_decrypt_attempts:
        Arc<Mutex<std::collections::HashMap<String, u8>>>,
    /// S6: hashes of mailbox envelope contents already processed this
    /// session — a hostile mailbox can re-wrap the same ciphertext under a
    /// fresh id; keyed dedup by sha256(content) catches what `message_exists`
    /// (id-keyed) cannot. Bounded; cleared on wipe.
    pub mailbox_seen_hashes:
        Arc<Mutex<std::collections::HashSet<String>>>,
    /// X25519 ECDH cipher (same persisted `dht.key` the node loads) — used to
    /// encrypt mailbox/pending envelopes for the recipient so the sender's
    /// local master key is never the fallback (recipient couldn't decrypt it).
    /// Populated when the P2P node starts — i.e. only after a successful login.
    /// Reset to `None` on wipe (a re-login must not reuse the stale cipher).
    pub dht_cipher: std::sync::Mutex<Option<Arc<crate::security::DHTCipher>>>,
    /// Login gate for the P2P node: the background task created in `setup`
    /// waits on this watch channel and builds the node only after login
    /// derived the master key (all key material lives behind the PIN).
    /// RC7: `P2PGate::seq` bumps on EVERY send — a watch channel coalesces,
    /// so a fast false→true pair (wipe + immediate re-login) would otherwise
    /// be invisible to the teardown watcher and leave a ghost node alive
    /// on wiped keys.
    pub p2p_start_tx: tokio::sync::watch::Sender<P2PGate>,
    /// RC12: bumped on every login/wipe — surviving spawned tasks (prekey
    /// publish, retry workers) compare their captured epoch and abort rather
    /// than writing stale identity material into a re-logged session.
    pub login_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// App log directory (tauri-plugin-log target) — wiped by KillPin so
    /// no message ids / peer ids survive in noid.log.
    pub app_log_dir: PathBuf,
    /// F11: peers with a live connection — fed by PeerConnected /
    /// PeerDisconnected so the pending-retry loop can flush directly
    /// instead of waiting for the mailbox cycle.
    pub connected_peers: Arc<Mutex<std::collections::HashSet<String>>>,
    /// TI-15: inbound file reassembly — keyed `from:offer_id`, entries hold
    /// received chunks until `total_chunks` arrives (then the file is
    /// written to `<app_data>/received/`). Bounded + TTL'd against
    /// abandoned transfers.
    pub file_inbox:
        Arc<Mutex<HashMap<String, crate::file_inbox::FileInboxEntry>>>,
}

/// A ratchet message we could not decrypt yet — kept for post-login retry.
pub struct BufferedInbound {
    pub id: String,
    pub msg: crate::security::RatchetMessage,
    pub timestamp: Option<String>,
}

/// P2P gate value — `open` is the desired state, `seq` is a monotonic
/// transition counter so watch-coalescing can never hide a false→true pair
/// from the teardown watcher (RC7). All sends go through [`gate_set`].
#[derive(Clone, Copy, Debug)]
pub struct P2PGate {
    pub open: bool,
    pub seq: u64,
}

/// RC28: shared "send NoidMessage to peer" — requires P2P (RC17 guard) and
/// goes through the bounded command send, so every send command reports
/// failures identically instead of re-implementing the `p2p()+map_err` block.
pub async fn send_message_to_peer(
    state: &AppState,
    peer_id: &str,
    msg: crate::p2p::NoidMessage,
) -> Result<(), String> {
    let tx = state.require_p2p()?;
    send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage {
        peer_id: peer_id.to_string(),
        msg,
    })
    .await
    .map_err(|e| e.to_string())
}

/// RC28: shared "dial peer before sending" preamble — requires P2P and asks
/// the node to (re)establish connectivity; the actual resolution is async.
pub async fn ensure_peer_connection(state: &AppState, peer_id: &str) -> Result<(), String> {
    let tx = state.require_p2p()?;
    send_p2p_cmd(&tx, crate::p2p::P2PCommand::ConnectToPeer {
        peer_id: peer_id.to_string(),
        addr_hint: None,
    })
    .await
    .map_err(|e| e.to_string())
}

/// Set the P2P gate desired-state, bumping `seq` unconditionally.
pub fn gate_set(tx: &tokio::sync::watch::Sender<P2PGate>, open: bool) {
    tx.send_modify(|g| {
        g.open = open;
        g.seq = g.seq.wrapping_add(1);
    });
}

/// RC22: `my_id` sentinel values — the peer id is never a valid destination
/// while the node is not yet started or was wiped. Centralized so callers
/// stop comparing against one literal and forgetting the other.
pub const MY_ID_PENDING: &str = "Loading...";
pub const MY_ID_WIPED: &str = "Wiped";

/// RC26: typed auth outcome — replaces magic `message` strings ("WIPED",
/// "Logged in") the frontend used to branch on.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuthOutcome {
    /// Credentials accepted; node unlocked.
    Ok,
    /// Kill PIN entered — data was wiped.
    Wiped,
    /// Temporarily locked out after failed attempts; `message` carries the wait.
    LockedOut,
    /// Generic failure; `message` carries details.
    Failed,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub kind: AuthOutcome,
    /// FE-03: seconds until the lockout lifts (`locked_out` responses only) —
    /// lets the UI show a live countdown instead of a static string.
    #[serde(default)]
    pub retry_after_secs: Option<u64>,
    /// FE-03: attempts left before the next failure locks the account
    /// (`failed` responses only).
    #[serde(default)]
    pub attempts_remaining: Option<u32>,
}

/// Clone the current P2P command sender out of the watch channel. The
/// `borrow()` Ref is confined to this function so the result is Send-safe
/// to hold across `.await` points (watch::Ref is !Send).
pub fn p2p_sender(
    tx: &tokio::sync::watch::Sender<
        Option<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>>,
    >,
) -> Option<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>> {
    tx.borrow().clone()
}

/// RC3: bounded P2P command dispatch. A bare `send().await` on the
/// 100-slot command channel blocks the caller forever when the event
/// loop is stalled (e.g. on event-channel backpressure — the classic
/// circular wait: cmd producer waits on cmd channel, event loop waits
/// on event channel, forwarder waits on a command). A 10s bound turns
/// livelock into a surfacable error instead.
pub async fn send_p2p_cmd(
    tx: &tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>,
    cmd: crate::p2p::P2PCommand,
) -> Result<(), String> {
    match tokio::time::timeout(std::time::Duration::from_secs(10), tx.send(cmd)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            log::warn!("P2P command dispatch failed: channel closed");
            Err(format!("P2P channel closed: {}", e))
        }
        Err(_) => {
            log::warn!("P2P command dispatch failed: channel blocked >10s");
            Err("P2P command channel blocked >10s".to_string())
        }
    }
}

impl AppState {
    /// The running node's command sender — `None` before login and after wipe.
    pub fn p2p(&self) -> Option<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>> {
        p2p_sender(&self.p2p_tx)
    }

    /// RC16/RC32: uniform DB guard — the leaf-snapshot `Database` or a
    /// surfaced error. Replaces the ~30 ad-hoc `db.lock()+if let Some`
    /// copies, several of which silently returned `Ok(())` for a no-op.
    pub async fn require_db(&self) -> Result<Database, String> {
        self.db
            .lock()
            .await
            .clone()
            .ok_or_else(|| "Database not initialized".to_string())
    }

    /// RC17/RC32: uniform P2P guard — the command sender or a surfaced
    /// error, replacing silent `Ok(())`-when-offline commands.
    pub fn require_p2p(
        &self,
    ) -> Result<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>, String> {
        self.p2p()
            .ok_or_else(|| "P2P not initialized".to_string())
    }

    /// RC22: our live peer id, or `None` while the node is not running
    /// (pre-login `Loading...` / post-wipe `Wiped` sentinels).
    pub async fn current_peer_id(&self) -> Option<String> {
        let id = self.my_id.lock().await.clone();
        if id.is_empty() || id == MY_ID_PENDING || id == MY_ID_WIPED {
            None
        } else {
            Some(id)
        }
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
            let app_data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
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
                undecrypted_inbound: Arc::new(Mutex::new(std::collections::HashMap::new())),
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
                app_log_dir,
                connected_peers: Arc::new(Mutex::new(std::collections::HashSet::new())),
                file_inbox: Arc::new(Mutex::new(HashMap::new())),
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
            let mut p2p_gate_rx = p2p_start_rx;
            // tauri::async_runtime::spawn — setup() runs on the main
            // thread with NO ambient Tokio runtime (tokio::spawn panics
            // there — crashes Android on startup).
            tauri::async_runtime::spawn(async move {
              // Loop so a KillPin wipe can tear the node down and a later
              // login spins up a fresh one — gate flips false → node aborted
              // → back to waiting for the next successful login.
              // RC8: consecutive unexpected node deaths back off
              // exponentially (1s→60s cap) instead of hot-looping the
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

                // Unlock node key material with the PIN-derived master key.
                // Legacy plaintext key files are migrated to the NOIDKEY1
                // envelope on first login after the upgrade.
                let app_state = handle.state::<AppState>();
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
                    let id_bytes = crate::security::key_store::load_or_regen(
                        &app_data_dir_clone.join("identity.key"),
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
                        &app_data_dir_clone.join("dht.key"),
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

                match P2PNode::new_with_keys(&app_data_dir_clone, local_key, dht_cipher, master_key).await {
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
                        let rejoin_handle = handle.clone();
                        login_tasks.push(tokio::spawn(async move {
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
                        }));
                    }

                    // DB maintenance once per login (DB11 orphan messages,
                    // DB24 contact-request TTL/cap, DB25 orphan ratchet
                    // states). Runs inside the login-epoch task set so it
                    // dies with the session.
                    {
                        let maint_handle = handle.clone();
                        login_tasks.push(tokio::spawn(async move {
                            let app_state = maint_handle.state::<AppState>();
                            let db = app_state.db.lock().await.clone();
                            let my_id = app_state.my_id.lock().await.clone();
                            if let Some(db) = db {
                                if let Err(e) = db.maintenance_cleanup(&my_id).await {
                                    log::warn!("maintenance_cleanup failed: {}", e);
                                }
                            }
                        }));
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
                    let publish_handle = handle.clone();
                    login_tasks.push(tokio::spawn(async move {
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
                    }));

                    // Periodic username republish to DHT (every 30 minutes)
                    let republish_handle = handle.clone();
                    login_tasks.push(tokio::spawn(async move {
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
                    }));

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
                    let mailbox_retry_handle = handle.clone();
                    login_tasks.push(tokio::spawn(async move {
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
                                                    tokio::spawn(async move {
                                                        crate::pending_flush::flush_pending_for_peer(&h, &p).await;
                                                    });
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
                    }));

                    // Phase I.1: Periodic mailbox retrieval — check our own mailbox every 5 minutes
                    let mailbox_retrieve_handle = handle.clone();
                    login_tasks.push(tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(10)).await; // Start after bootstrap
                        let mut interval = interval(Duration::from_secs(300)); // 5 minutes
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
                    }));

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
                            for h in login_tasks { h.abort(); }
                        });
                    }

                    // Forward events to frontend
                    // Relay-status events fire on every connection/reservation
                    // churn — dedupe so identical snapshots don't spam the log
                    // and re-render the UI. Only a real change is emitted.
                    let mut last_relay_status: Option<crate::p2p::relay_status::RelayStatus> = None;
                    while let Some(event) = event_rx.recv().await {
                        match event {
                            P2PEvent::NewListenAddr(addr) => {
                                safe_emit(&handle, "p2p-event", format!("Listening on {}", addr));
                            }
                            P2PEvent::PeerDiscovered(peer, addr) => {
                                safe_emit(&handle, "p2p-event", format!("Discovered {} at {}", peer, addr));
                                // No pending flush here: discovery (mDNS) fires before a
                                // connection exists, and this path used to send raw
                                // plaintext Chat messages. The PeerConnected handler
                                // flushes pending with ratchet encryption instead.
                            }
                            P2PEvent::MessageReceived { from, data } => {
                                safe_emit(&handle, "chat-msg", serde_json::json!({"from": from, "data": data}));
                            }
                            P2PEvent::RequestReceived { from, data } => {
                                // RC10: spawn per request — decrypt + DB must
                                // not serialize the event forwarder (an inbound
                                // storm would backpressure the swarm's emit_ev).
                                // TI-1: application-level ack — the response
                                // channel parked in the node is answered only
                                // after the payload reached durable state.
                                // None = leave unanswered so the sender
                                // request times out and the message re-pends.
                                // CR-03: same-peer requests run FIFO under a
                                // per-peer lock — an X3DHInit task stalled on
                                // SQLite was overtaken by the RatchetChat
                                // right behind it and lost the session race.
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    let peer_lock = {
                                        let app_state = h.state::<AppState>();
                                        let mut locks = app_state.inbound_peer_locks.lock().await;
                                        locks
                                            .entry(from.clone())
                                            .or_insert_with(|| {
                                                Arc::new(tokio::sync::Mutex::new(()))
                                            })
                                            .clone()
                                    };
                                    let _peer_guard = peer_lock.lock().await;
                                    let ack_status = crate::request_dispatch::handle_request_received(
                                        &h, &from, &data,
                                    )
                                    .await;
                                    if let Some(status) = ack_status {
                                        let app_state = h.state::<AppState>();
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckReceived {
                                                    peer_id: from,
                                                    message_id: data.id.clone(),
                                                    status: status.to_string(),
                                                })
                                                .await;
                                        }
                                    }
                                });
                            }
                            P2PEvent::RoomMessage { room_id, sender, content, msg_id, ts } => {
                                // RC10: DB write off the forwarder path.
                                // Verified + decrypted room envelope — persist and notify UI.
                                // The PK dedup doubles as the emit gate: a copy that
                                // already arrived out-of-band (RoomChat direct/mailbox)
                                // must not emit a second room-msg — the in-memory
                                // seen_room_msgs cache is empty after a restart.
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db_state = app_state.db.lock().await;
                                    let inserted = if let Some(db) = db_state.as_ref() {
                                        db
                                            .add_room_message(&msg_id, &room_id, &sender, content.as_bytes(), &ts)
                                            .await
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    };
                                    drop(db_state);
                                    if inserted {
                                        safe_emit(&h, "room-msg", serde_json::json!({
                                            "room_id": room_id,
                                            "sender": sender,
                                            "content": content,
                                            "msg_id": msg_id,
                                            "ts": ts,
                                        }));
                                    }
                                });
                            }
                            P2PEvent::RoomControl { room_id, sender, payload } => {
                                // RC10: spawn — the dispatcher authorizes and may
                                // hit the DB/network; do not stall the forwarder.
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    if let Ok(p) = serde_json::from_str::<crate::p2p::RoomPayload>(&payload) {
                                        crate::room_rekey::dispatch_room_topic_payload(
                                            &h, &room_id, &sender, p,
                                        ).await;
                                    }
                                });
                            }
                            P2PEvent::RoomKeyStale { room_id } => {
                                // Signed envelope failed to open — our stored
                                // key is stale; ask the owner for the current one.
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    crate::room_control::request_key_sync(&h, &room_id).await;
                                });
                            }
                            P2PEvent::PeerConnected(peer) => {
                                // A live connection IS the online fact — no
                                // Ping/Pong probes involved anymore.
                                safe_emit(&handle, "peer-connected", &peer);
                                safe_emit(&handle, "peer-online", &peer);
                                handle.state::<AppState>()
                                    .connected_peers.lock().await.insert(peer.clone());

                                let app_state = handle.state::<AppState>();

                                // Phase 0.3: Removed auto-send public key on PeerConnected.
                                // Keys are exchanged only on ContactRequest or when a key changes,
                                // preventing the PublicKeyExchange ping-pong that triggered deadlocks.

                                // Phase I.2: Trigger mailbox retrieval for self when a peer connects
                                // (messages may have been stored on a mailbox node while we were offline)
                                {
                                    if let Some(my_id) = app_state.current_peer_id().await {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                                peer_id: my_id,
                                            }).await;
                                        }
                                    }
                                }

                                // RC10: flush + rekey resend spawn off the
                                // forwarder — they walk the whole pending table
                                // and dial out; a connect storm would otherwise
                                // serialize the event loop for seconds.
                                // NOTE: the db guard MUST be dropped before resend_owned_keys()
                                // — that function locks app_state.db itself, and tokio's
                                // Mutex is not reentrant (this self-deadlock froze every
                                // DB-backed command after the first PeerConnected).
                                {
                                    let h = handle.clone();
                                    let peer_c = peer.clone();
                                    tokio::spawn(async move {
                                        // RC2: snapshot Database (shared pool), release the
                                        // guard before my_id/security locks inside the loop.
                                        // F11: extracted into pending_flush — the
                                        // retry loop reuses this for connected peers.
                                        crate::pending_flush::flush_pending_for_peer(&h, &peer_c).await;

                                        // Reconnect self-heal: if this peer is a member of a
                                        // room we own, resend the current KeyUpdate — covers
                                        // rekeys that happened while they were offline.
                                        crate::room_rekey::resend_owned_keys(&h, &peer_c).await;
                                    });
                                }
                            }
                            P2PEvent::PeerDisconnected(peer) => {
                                safe_emit(&handle, "peer-disconnected", &peer);
                                let app_state = handle.state::<AppState>();
                                app_state.connected_peers.lock().await.remove(&peer);
                                // F11: a contact we owe pending messages to gets a
                                // planned re-dial (ConnectToPeer resolves addrs via
                                // the DHT/cache; dial backoff inside the node bounds
                                // the churn). RC10: DB lookup off the forwarder.
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db = app_state.db.lock().await.clone();
                                    if let Some(db) = db {
                                        let has_pending = db
                                            .get_pending_messages(&peer)
                                            .await
                                            .map(|p| !p.is_empty())
                                            .unwrap_or(false);
                                        if has_pending {
                                            if let Some(tx) = app_state.p2p() {
                                                let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::ConnectToPeer {
                                                    peer_id: peer.clone(),
                                                    addr_hint: None,
                                                }).await;
                                            }
                                        }
                                    }
                                });
                            }
                            P2PEvent::PeerOnline(peer) => {
                                safe_emit(&handle, "peer-online", &peer);
                            }
                            P2PEvent::MessageFailed { to, request_id: _, error, content, message_id, msg_type } => {
                                log::warn!("Message failed to send to {}: {}", to, error);

                                // Chat/RatchetChat get the plaintext pending/mailbox
                                // fallback. Typed messages (RoomControl, RoomInvite,
                                // ContactRequest, ContactAccept) carry a structured
                                // payload — they are re-pended as a serialized
                                // NoidMessage ("NOIDMSG1:") and resent verbatim on
                                // reconnect or via mailbox, so a contact request
                                // survives the recipient being offline.
                                let typed = matches!(
                                    msg_type,
                                    crate::p2p::MessageType::RoomControl { .. }
                                        | crate::p2p::MessageType::RoomChat { .. }
                                        | crate::p2p::MessageType::RoomInvite { .. }
                                        | crate::p2p::MessageType::RoomInviteOffer { .. }
                                        | crate::p2p::MessageType::RoomInviteAccept { .. }
                                        | crate::p2p::MessageType::RoomInviteDecline { .. }
                                        | crate::p2p::MessageType::ContactRequest { .. }
                                        | crate::p2p::MessageType::ContactAccept { .. }
                                        // A dropped X3DHInit leaves the peers
                                        // permanently desynced — it must retry
                                        // through pending/mailbox like the rest.
                                        | crate::p2p::MessageType::X3DHInit { .. }
                                );
                                if !typed && !matches!(msg_type, crate::p2p::MessageType::Chat(_) | crate::p2p::MessageType::RatchetChat { .. }) {
                                    log::debug!("Skipping pending/mailbox fallback for non-chat message type");
                                    continue;
                                }
                                // TI-3: emit only for user-visible chat failures
                                // (a dropped Ping/ReadReceipt must not mark the
                                // whole chat failed) and carry the message id so
                                // the frontend marks the single message.
                                safe_emit(&handle, "message-failed", serde_json::json!({
                                    "to": &to, "error": &error, "message_id": &message_id
                                }));

                                // RC10: re-pend + mailbox lookup spawn off the
                                // forwarder — DB writes and DHT lookups must not
                                // serialize other events.
                                let h = handle.clone();
                                let to = to.clone();
                                tokio::spawn(async move {
                                let app_state = h.state::<AppState>();

                                // Re-pend the failed message under its ORIGINAL message_id —
                                // send_chat_message already stored it, so this mainly covers
                                // messages sent from other paths. The exists-check prevents
                                // duplicate pending rows (which would resend twice).
                                {
                                    // RC2: db snapshot — encode_pending_content
                                    // locks `security` internally; the global db
                                    // guard must not be held across it.
                                    let db = app_state.db.lock().await.clone();
                                    if let Some(db) = db {
                                        let already_pending = !message_id.is_empty()
                                            && db.pending_exists_by_message_id(&to, &message_id).await.unwrap_or(false);
                                        if already_pending {
                                            log::debug!("Message {} already in pending, not re-adding", message_id);
                                        } else if typed {
                                            let effective_id = if message_id.is_empty() {
                                                uuid::Uuid::new_v4().to_string()
                                            } else {
                                                message_id.clone()
                                            };
                                            let my_id = app_state.my_id.lock().await.clone();
                                            let reconstructed = crate::p2p::NoidMessage {
                                                sender: my_id,
                                                content: content.clone(),
                                                msg_type: msg_type.clone(),
                                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                id: effective_id.clone(),
                                            };
                                            match serde_json::to_string(&reconstructed) {
                                                Ok(json) => {
                                                    let body = format!("NOIDMSG1:{}", json);
                                                    match encode_pending_content(&app_state.security, &body).await {
                                                        Some(enc) => {
                                                            if let Err(e) = db.add_pending_message_with_content(&to, &enc, &effective_id).await {
                                                                log::error!("Failed to re-pend typed message {} for {}: {}", effective_id, to, e);
                                                            } else {
                                                                log::debug!("Typed message {} saved to pending_messages for {}", effective_id, to);
                                                            }
                                                        }
                                                        None => {
                                                            log::error!("Cannot persist failed message for {}: master key unavailable", to);
                                                        }
                                                    }
                                                }
                                                Err(e) => log::warn!("Cannot serialize typed message for pending: {}", e),
                                            }
                                        } else if content.is_empty() {
                                            // RatchetChat failures carry no plaintext (by design) —
                                            // without a pending row we cannot reconstruct the body.
                                            log::warn!("Failed message {} has no pending row and no recoverable body", message_id);
                                        } else {
                                            let effective_id = if message_id.is_empty() {
                                                uuid::Uuid::new_v4().to_string()
                                            } else {
                                                message_id.clone()
                                            };
                                            match encode_pending_content(&app_state.security, &content).await {
                                                Some(enc) => {
                                                    if let Err(e) = db.add_pending_message_with_content(&to, &enc, &effective_id).await {
                                                        log::error!("Failed to re-pend message {} for {}: {}", effective_id, to, e);
                                                    } else {
                                                        log::debug!("Message {} saved to pending_messages for {}", effective_id, to);
                                                    }
                                                }
                                                None => {
                                                    log::error!("Cannot persist failed message for {}: master key unavailable", to);
                                                }
                                            }
                                        }
                                    }
                                }

                                // Offline delivery goes through the recipient's mailbox node —
                                // the deprecated DHT message store is no longer written to.
                                if let Some(tx) = app_state.p2p() {
                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FindMailboxNode {
                                        peer_id: to.clone(),
                                    }).await;
                                    log::debug!("Triggered mailbox lookup for {} after send failure", to);
                                }
                                });
                            }
                            P2PEvent::MessageDelivered { peer_id, message_id } => {
                                // Phase 1.3: Delete pending message on confirmed delivery —
                                // scoped to (peer, id): a room fan-out ack must not
                                // remove another member's pending row.
                                // RC10: DB write off the forwarder path.
                                let h = handle.clone();
                                let (peer_id_c, message_id_c) = (peer_id.clone(), message_id.clone());
                                tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db_state = app_state.db.lock().await;
                                    if let Some(db) = db_state.as_ref() {
                                        if let Err(e) = db.delete_pending_message_by_id(&peer_id_c, &message_id_c).await {
                                            log::warn!("Failed to delete pending {} after delivery: {}", message_id_c, e);
                                        } else {
                                            log::debug!("Deleted pending message {} after delivery confirmation", message_id_c);
                                        }
                                    }
                                });
                                safe_emit(&handle, "message-delivered", serde_json::json!({
                                    "peer_id": &peer_id,
                                    "message_id": &message_id,
                                }));
                            }
                            P2PEvent::UsernameAvailabilityChecked { username, available, uncertain } => {
                                safe_emit(&handle, "username-availability", serde_json::json!({
                                    "username": &username,
                                    "available": available,
                                    "uncertain": uncertain,
                                }));
                            }
                            P2PEvent::UserLookupResult { username, record } => {
                                if let Some(ref rec) = record {
                                    log::debug!("User lookup result: found user '{}' with peer_id {}", username, rec.peer_id);
                                } else {
                                    log::debug!("User lookup result: no user found for '{}'", username);
                                }
                                safe_emit(&handle, "user-lookup-result", serde_json::json!({
                                    "username": &username,
                                    "record": record,
                                }));
                            }
                            P2PEvent::PrekeyBundleRetrieved { peer_id, bundle } => {
                                match bundle {
                                    Some(b) => {
                                        log::debug!("Prekey bundle retrieved for peer {}", peer_id);
                                        // Phase A.4: Initiate X3DH session with the retrieved bundle
                                        let app_state = handle.state::<AppState>();
                                        let sessions = app_state.ratchet_sessions.clone();
                                        let db = app_state.db.clone();
                                        let p2p_tx = app_state.p2p_tx.clone();
                                        let audit_log = app_state.audit_log.clone();
                                        let security_arc = app_state.security.clone();
                                        let my_id_for_retry = app_state.my_id.lock().await.clone();
                                        let peer_id_owned = peer_id.clone();
                                        tokio::spawn(async move {
                                            match sessions.initiate_session(&peer_id_owned, &b).await {
                                                Ok(initial_msg) => {
                                                    log::info!("X3DH session initiated with {}", peer_id_owned);
                                                    // Phase E: Log key exchange
                                                    let _ = audit_log.log_key_exchange(&peer_id_owned);
                                                    // MD-01: persist the peer's X25519 identity
                                                    // from the signed bundle — the mailbox
                                                    // envelope path needs it for
                                                    // encrypt_for_recipient before any
                                                    // direct PublicKeyExchange happened.
                                                    let session_db = match crate::persist_initiated_session::persist_initiated_session(
                                                        &db, &sessions, &peer_id_owned, &b.identity_public,
                                                    ).await {
                                                        Ok(db) => db,
                                                        Err(e) => {
                                                            log::error!("Failed to persist initiated session for {}: {}", peer_id_owned, e);
                                                            return;
                                                        }
                                                    };
                                                    log::info!("X3DH session persisted for {}", peer_id_owned);
                                                    // Send X3DHInit message to peer
                                                    let noid_msg = crate::p2p::types::NoidMessage {
                                                        id: uuid::Uuid::new_v4().to_string(),
                                                        msg_type: crate::p2p::types::MessageType::X3DHInit {
                                                            identity_public: initial_msg.identity_public.clone(),
                                                            ephemeral_public: initial_msg.ephemeral_public.clone(),
                                                            one_time_prekey_id: initial_msg.one_time_prekey_id.clone(),
                                                            // S21: signed by the node at send time.
                                                            identity_signature: Vec::new(),
                                                        },
                                                        sender: String::new(),
                                                        content: String::new(),
                                                        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                    };
                                                    // F13/F15: pend the X3DHInit BEFORE queueing — a dropped
                                                    // init leaves peers desynced, and the crash window between
                                                    // enqueue and OutboundFailure must not lose it.
                                                    {
                                                        if let Ok(json) = serde_json::to_string(&noid_msg) {
                                                            if let Some(enc) = encode_pending_content(&security_arc, &format!("NOIDMSG1:{}", json)).await {
                                                                if let Err(e) = session_db.add_pending_message_with_content(&peer_id_owned, &enc, &noid_msg.id).await {
                                                                    log::error!("Failed to pend X3DHInit {} for {}: {}", noid_msg.id, peer_id_owned, e);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        if let Err(e) = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                            peer_id: peer_id_owned.clone(),
                                                            msg: noid_msg,
                                                        }).await {
                                                            log::error!("Failed to send X3DHInit: {}", e);
                                                        }
                                                    }
                                                    // Phase G.2: Auto-retry pending messages now that session is established.
                                                    // Wait 1s for X3DHInit to be delivered, then encrypt + send queued messages.
                                                    let db_for_retry = db.clone();
                                                    let sessions_for_retry = sessions.clone();
                                                    let p2p_tx_for_retry = p2p_tx.clone();
                                                    let security_for_retry = security_arc.clone();
                                                    let my_id_for_retry2 = my_id_for_retry.clone();
                                                    let peer_id_for_retry = peer_id_owned.clone();
                                                    tokio::spawn(async move {
                                                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                                        // RC2: snapshot Database —
                                                        // decode_pending_content locks
                                                        // `security`, the global db
                                                        // guard must not be held here.
                                                        let db = db_for_retry.lock().await.clone();
                                                        if let Some(db) = db {
                                                            if let Ok(pending) = db.get_pending_messages(&peer_id_for_retry).await {
                                                                for (id, raw_content, message_id) in pending {
                                                                    let Some(content) = decode_pending_content(&security_for_retry, &raw_content).await else {
                                                                        log::warn!("Pending row {} undecryptable — skipped", id);
                                                                        continue;
                                                                    };
                                                                    if let Some(json) = content.strip_prefix("NOIDMSG1:") {
                                                                        if let Ok(msg) = serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                                                                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                                                                // send() only enqueues — the row
                                                                                // is deleted on MessageDelivered.
                                                                                let _ = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                                                    peer_id: peer_id_for_retry.clone(),
                                                                                    msg,
                                                                                }).await;
                                                                            }
                                                                        }
                                                                        continue;
                                                                    }
                                                                    match sessions_for_retry.encrypt(&peer_id_for_retry, content.as_bytes()).await {
                                                                        Ok(Some(ratchet_msg)) => {
                                                                            let noid_msg = crate::p2p::types::NoidMessage {
                                                                                id: message_id.clone(),
                                                                                sender: my_id_for_retry2.clone(),
                                                                                content: String::new(),
                                                                                msg_type: crate::p2p::types::MessageType::RatchetChat {
                                                                                    ciphertext: ratchet_msg.ciphertext,
                                                                                    header_dh_public: ratchet_msg.header.dh_public,
                                                                                    header_pn: ratchet_msg.header.pn,
                                                                                    header_n: ratchet_msg.header.n,
                                                                                },
                                                                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                                                            };
                                                                            if let Some(tx) = p2p_sender(&p2p_tx_for_retry) {
                                                                                let _ = send_p2p_cmd(&tx, crate::p2p::types::P2PCommand::SendMessage {
                                                                                    peer_id: peer_id_for_retry.clone(),
                                                                                    msg: noid_msg,
                                                                                }).await;
                                                                            }
                                                                            // Row stays until MessageDelivered.
                                                                        }
                                                                        _ => log::warn!("Failed to encrypt pending message {}", message_id),
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to initiate X3DH session with {}: {}", peer_id_owned, e);
                                                }
                                            }
                                        });
                                    }
                                    None => {
                                        log::warn!("No prekey bundle found for peer {}", peer_id);
                                        safe_emit(&handle, "message-failed", serde_json::json!({
                                            "to": &peer_id,
                                            "error": "No prekey bundle found — cannot establish E2EE session",
                                        }));
                                    }
                                }
                            }
                            P2PEvent::MailboxMessagesRetrieved { mailbox_peer_id, messages } => {
                                log::debug!("Retrieved {} messages from mailbox {}", messages.len(), mailbox_peer_id);
                                // Phase I.3: Process retrieved mailbox messages — decrypt, save to DB, emit, ack
                                let app_state = handle.state::<AppState>();
                                let db = app_state.db.clone();
                                let sessions = app_state.ratchet_sessions.clone();
                                let security = app_state.security.clone();
                                let dht_cipher = app_state.dht_cipher.lock()
                                    .map(|g| g.clone())
                                    .unwrap_or_else(|e| {
                                        log::error!("dht_cipher lock poisoned: {}", e);
                                        None
                                    });
                                let p2p_tx = app_state.p2p_tx.clone();
                                let handle_clone = handle.clone();
                                let decrypt_attempts = app_state.mailbox_decrypt_attempts.clone();
                                let mailbox_seen_hashes = app_state.mailbox_seen_hashes.clone();
                                let mailbox_peer_id_clone = mailbox_peer_id.clone();
                                let my_id = app_state.my_id.lock().await.clone();
                                tokio::spawn(async move {
                                    // RC1: never hold the global db mutex across
                                    // dispatch calls — apply_room_control /
                                    // dispatch_contact_message / handle_x3dh_init
                                    // re-lock it through the AppHandle. Clone a
                                    // Database snapshot (shared pool + cipher) and
                                    // drop the guard immediately.
                                    let db = {
                                        let db_guard = db.lock().await;
                                        match db_guard.clone() {
                                            Some(d) => d,
                                            None => {
                                                log::error!("Mailbox processing: database not initialized");
                                                return;
                                            }
                                        }
                                    };
                                    {
                                        for item in messages {
                                            let msg_id = item.id;
                                            let sender = item.sender;
                                            let content = item.content;
                                            let timestamp = item.timestamp;
                                            // S6: verify the sender's envelope signature end-to-end —
                                            // the mailbox is a courier, not an authority. Try the v2
                                            // payload (binds client_msg_id) first, then legacy v1.
                                            let sig_ok = !item.signature.is_empty() && (
                                                crate::security::identity_sig::verify_payload(
                                                    &sender,
                                                    &crate::p2p::types::envelope_signing_payload_v2(
                                                        &my_id, &sender, &msg_id, &content,
                                                    ),
                                                    &item.signature,
                                                ) || crate::security::identity_sig::verify_payload(
                                                    &sender,
                                                    &crate::p2p::types::envelope_signing_payload(
                                                        &my_id, &sender, &content,
                                                    ),
                                                    &item.signature,
                                                )
                                            );
                                            if !sig_ok {
                                                log::warn!(
                                                    "Mailbox envelope {} from {} — signature missing/invalid, dropped",
                                                    msg_id, sender
                                                );
                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                        mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                        message_id: msg_id,
                                                    }).await;
                                                }
                                                continue;
                                            }
                                            // S6: freshness — the mailbox assigns a timestamp and the
                                            // envelope expires after 7 days; a replayed/stale copy or a
                                            // far-future timestamp is dropped (1-day clock-skew slack).
                                            let stale = chrono::DateTime::parse_from_rfc3339(&timestamp)
                                                .map(|ts| {
                                                    let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
                                                    age > chrono::Duration::days(8) || age < chrono::Duration::days(-1)
                                                })
                                                .unwrap_or(true);
                                            if stale {
                                                log::warn!(
                                                    "Mailbox envelope {} from {} — stale timestamp {}, dropped",
                                                    msg_id, sender, timestamp
                                                );
                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                        mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                        message_id: msg_id,
                                                    }).await;
                                                }
                                                continue;
                                            }
                                            // S6: content-hash dedup — a hostile mailbox can re-wrap
                                            // the same ciphertext under a fresh message id; the id-keyed
                                            // check below cannot catch that.
                                            let content_hash = {
                                                use sha2::{Digest, Sha256};
                                                let mut h = Sha256::new();
                                                h.update(&content);
                                                hex::encode(h.finalize())
                                            };
                                            {
                                                // MD-02: CHECK-ONLY here —
                                                // inserting the hash before
                                                // decryption made a first
                                                // failed attempt mark the
                                                // envelope "seen", so the
                                                // next Retrieve acked it as
                                                // replay WITHOUT decrypting
                                                // and MAX_DECRYPT_ATTEMPTS
                                                // never reached 2/6.
                                                let seen = mailbox_seen_hashes.lock().await;
                                                if seen.contains(&content_hash) {
                                                    log::debug!("Skipping replayed mailbox content (msg {})", msg_id);
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                            mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                            message_id: msg_id,
                                                        }).await;
                                                    }
                                                    continue;
                                                }
                                            }
                                            // Dedup: the same envelope can arrive from a second
                                            // mailbox replica or race with a direct resend — the
                                            // mailbox still gets an ack, but we don't re-process.
                                            if db.message_exists(&msg_id).await.unwrap_or(false) {
                                                log::debug!("Skipping duplicate mailbox message {}", msg_id);
                                                // Already processed earlier —
                                                // safe to mark seen and ack.
                                                let mut seen = mailbox_seen_hashes.lock().await;
                                                if seen.len() < 10_000 {
                                                    seen.insert(content_hash.clone());
                                                }
                                                drop(seen);
                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                        mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                        message_id: msg_id,
                                                    }).await;
                                                }
                                                continue;
                                            }

                                            // Try to decrypt as a ratchet message first
                                            let plaintext_opt = if let Ok(ratchet_msg) = serde_json::from_slice::<crate::security::RatchetMessage>(&content) {
                                                if !sessions.has_session(&sender).await {
                                                    let _ = sessions.load_session(&db, &sender).await;
                                                }
                                                match sessions.decrypt(&sender, &ratchet_msg).await {
                                                    Ok(plaintext) => Some(plaintext),
                                                    Err(e) => {
                                                        log::warn!("Failed to decrypt mailbox message from {} as ratchet: {}", sender, e);
                                                        // S5: replayed envelopes (hostile mailbox re-issuing
                                                        // old ciphertext under a fresh mailbox id) fail AEAD
                                                        // on a consumed position — not desync, don't count.
                                                        if sessions.is_replay_message(&sender, &ratchet_msg).await {
                                                            log::debug!("Ignoring replayed mailbox ratchet message from {}", sender);
                                                        } else if sessions.has_session(&sender).await {
                                                            // Count toward desync detection — the direct
                                                            // path does the same; mailbox-delivered
                                                            // desyncs otherwise never trigger recovery.
                                                            let fails = sessions
                                                                .record_decrypt_failure(&sender).await;
                                                            if fails >= 3
                                                                && sessions.should_rehandshake(&sender).await
                                                            {
                                                                log::info!(
                                                                    "Ratchet desync with {} ({} mailbox failures) — re-handshaking",
                                                                    sender, fails
                                                                );
                                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::FetchPrekeyBundle {
                                                                        peer_id: sender.clone(),
                                                                    }).await;
                                                                }
                                                            }
                                                        }
                                                        None
                                                    }
                                                }
                                            } else {
                                                // ECDH envelope for our DHT key (senders without a
                                                // ratchet session use encrypt_for_recipient).
                                                match serde_json::from_slice::<crate::security::DHTEncryptedMessage>(&content) {
                                                    Ok(envelope) => match dht_cipher.as_ref() {
                                                        Some(cipher) => match cipher.decrypt_message(&envelope) {
                                                            Ok(plaintext) => Some(plaintext),
                                                            Err(e) => {
                                                                log::warn!("Failed to decrypt mailbox envelope from {}: {}", sender, e);
                                                                None
                                                            }
                                                        },
                                                        None => {
                                                            log::warn!("DHT cipher unavailable — cannot decrypt mailbox envelope");
                                                            None
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::warn!("Unrecognized mailbox envelope from {}: {}", sender, e);
                                                        None
                                                    }
                                                }
                                            };

                                            // Ack (mailbox deletes the envelope) only when the copy
                                            // is already stored or this one is persisted below.
                                            let mut processed = false;

                                            // S6: freshness — mailbox records live ≤24h, so an envelope
                                            // timestamped beyond that (or future-dated) is a replay.
                                            let stale = chrono::DateTime::parse_from_rfc3339(&timestamp)
                                                .ok()
                                                .map(|ts| {
                                                    let age = chrono::Utc::now() - ts.with_timezone(&chrono::Utc);
                                                    age.num_seconds() > 48 * 3600
                                                        || age.num_seconds() < -7200
                                                })
                                                .unwrap_or(true);
                                            if stale {
                                                log::warn!("Mailbox envelope {} rejected — stale/missing timestamp", msg_id);
                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                        mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                        message_id: msg_id,
                                                    }).await;
                                                }
                                                continue;
                                            }

                                            if let Some(plaintext) = plaintext_opt {
                                                let text = String::from_utf8_lossy(&plaintext).to_string();
                                                log::debug!("Decrypted mailbox message from {}", sender);
                                                // Save ratchet state so later restart can still decrypt
                                                // subsequent messages from this peer.
                                                let _ = sessions.save_session(&db, &sender).await;

                                                // Typed messages (room control/invites) are not chat —
                                                // dispatch them through the room control plane instead
                                                // of storing a JSON blob as a message.
                                                let typed_handled = match text.strip_prefix("NOIDMSG1:") {
                                                    Some(json) => match serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                                                        Ok(msg) => match &msg.msg_type {
                                                            crate::p2p::MessageType::RoomControl { room_id, wrapped_payload } => {
                                                                crate::room_control::apply_room_control(&handle_clone, room_id, &sender, wrapped_payload).await
                                                            }
                                                            crate::p2p::MessageType::RoomChat { room_id, envelope } => {
                                                                crate::room_control::apply_room_chat(&handle_clone, room_id, envelope).await;
                                                                true
                                                            }
                                                            crate::p2p::MessageType::RoomInvite { room_id, wrapped_key } => {
                                                                crate::room_control::apply_room_invite(&handle_clone, room_id, &sender, wrapped_key).await
                                                            }
                                                            crate::p2p::MessageType::RoomInviteOffer { room_id, wrapped_meta } => {
                                                                crate::room_control::apply_room_offer(&handle_clone, room_id, &sender, wrapped_meta).await
                                                            }
                                                            crate::p2p::MessageType::RoomInviteAccept { room_id } => {
                                                                crate::room_control::handle_room_invite_accept(&handle_clone, room_id, &sender).await;
                                                                true
                                                            }
                                                            crate::p2p::MessageType::RoomInviteDecline { room_id } => {
                                                                crate::room_control::handle_room_invite_decline(&handle_clone, room_id, &sender).await;
                                                                true
                                                            }
                                                            crate::p2p::MessageType::ContactRequest { .. }
                                                            | crate::p2p::MessageType::ContactAccept { .. } => {
                                                                crate::contact_dispatch::dispatch_contact_message(&handle_clone, &sender, &msg).await
                                                            }
                                                            // A mailbox-delivered handshake re-syncs a
                                                            // desynced pair — handle it like the direct
                                                            // path instead of storing it as chat text.
                                                            crate::p2p::MessageType::X3DHInit { identity_public, ephemeral_public, one_time_prekey_id, identity_signature } => {
                                                                x3dh_dispatch::handle_x3dh_init(
                                                                    &handle_clone,
                                                                    sender.clone(),
                                                                    identity_public,
                                                                    ephemeral_public,
                                                                    one_time_prekey_id,
                                                                    identity_signature,
                                                                ).await;
                                                                true
                                                            }
                                                            _ => false,
                                                        },
                                                        Err(_) => false,
                                                    },
                                                    None => false,
                                                };

                                                if typed_handled {
                                                    processed = true;
                                                } else {
                                                    let encrypted_for_storage = {
                                                        let security_guard = security.lock().await;
                                                        security_guard.encrypt(&plaintext).ok()
                                                    };
                                                    match encrypted_for_storage {
                                                        Some(enc) => {
                                                            match db.add_message_if_absent(&msg_id, &sender, &my_id, &enc, &timestamp).await {
                                                                Ok(true) => {
                                                                    safe_emit(&handle_clone, "chat-msg", serde_json::json!({
                                                                        "from": &sender,
                                                                        "data": {
                                                                            "content": &text,
                                                                            "id": &msg_id,
                                                                            "sender": &sender,
                                                                            "timestamp": &timestamp,
                                                                        }
                                                                    }));
                                                                    crate::android_bridge::notify_new_message(&handle_clone, &sender);
                                                                    processed = true;
                                                                }
                                                                Ok(false) => {
                                                                    // Lost the insert race to another retrieval
                                                                    // or a direct resend — already stored.
                                                                    log::debug!("Mailbox message {} already stored", msg_id);
                                                                    processed = true;
                                                                }
                                                                Err(e) => {
                                                                    log::warn!("Failed to store mailbox message {}: {}", msg_id, e);
                                                                }
                                                            }
                                                        }
                                                        None => {
                                                            log::warn!("Failed to encrypt mailbox message {} for storage", msg_id);
                                                        }
                                                    }
                                                }
                                            }

                                            if processed {
                                                // S6: attempts are keyed by
                                                // content hash, not the
                                                // mailbox-chosen id.
                                                decrypt_attempts.lock().await.remove(&content_hash);
                                                // MD-02: mark seen only now
                                                // that the envelope was
                                                // durably processed — a
                                                // failed decrypt stays
                                                // unseen so the next
                                                // Retrieve retries it.
                                                let mut seen = mailbox_seen_hashes.lock().await;
                                                if seen.len() < 10_000 {
                                                    seen.insert(content_hash.clone());
                                                }
                                                drop(seen);
                                                if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                    let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                        mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                        message_id: msg_id,
                                                    }).await;
                                                }
                                            } else {
                                                // A ciphertext from a dead ratchet
                                                // state can never decrypt — after
                                                // enough attempts it is poison
                                                // churning re-handshakes; ack+drop.
                                                const MAX_DECRYPT_ATTEMPTS: u8 = 6;
                                                // RC24: cap the attempts map — a
                                                // flood of distinct poisoned
                                                // envelopes must not grow it
                                                // without bound between GCs.
                                                const MAX_TRACKED: usize = 5000;
                                                let mut attempts = decrypt_attempts.lock().await;
                                                if attempts.len() >= MAX_TRACKED {
                                                    attempts.clear();
                                                }
                                                let n = attempts.entry(content_hash.clone()).or_insert(0);
                                                *n = n.saturating_add(1);
                                                if *n >= MAX_DECRYPT_ATTEMPTS {
                                                    attempts.remove(&content_hash);
                                                    drop(attempts);
                                                    log::warn!(
                                                        "Dropping undecryptable mailbox message {} after {} attempts",
                                                        msg_id, MAX_DECRYPT_ATTEMPTS
                                                    );
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckMailboxMessage {
                                                            mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                            message_id: msg_id,
                                                        }).await;
                                                    }
                                                } else {
                                                    log::warn!(
                                                        "Keeping undecrypted mailbox message {} for retry ({}/{})",
                                                        msg_id, n, MAX_DECRYPT_ATTEMPTS
                                                    );
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            P2PEvent::MailboxStoreAck { success, message_id, recipient_peer_id } => {
                                log::debug!("Mailbox store acknowledged: success={}", success);
                                if success {
                                    // The mailbox confirmed the store — only now
                                    // is the pending row safe to delete, scoped
                                    // to the actual recipient.
                                    if let Some(id) = message_id {
                                        let app_state = handle.state::<AppState>();
                                        let db_state = app_state.db.lock().await;
                                        if let Some(db) = db_state.as_ref() {
                                            if let Err(e) = db.delete_pending_message_by_id(&recipient_peer_id, &id).await {
                                                log::warn!("Failed to delete pending {} after mailbox store: {}", id, e);
                                            }
                                        }
                                        // DB27: emit only for Store-acks (id
                                        // present) — Delete-acks used to
                                        // produce phantom "stored" toasts.
                                        // TI-8/TI-4: carry ids so the UI can
                                        // mark THAT message as queued for
                                        // offline delivery (honest status —
                                        // stored ≠ peer-read).
                                        safe_emit(&handle, "mailbox-stored", serde_json::json!({
                                            "peer_id": &recipient_peer_id,
                                            "message_id": &id,
                                        }));
                                    }
                                } else {
                                    // Store failed or never reached the mailbox —
                                    // the pending row stays for the next retry.
                                    log::warn!("Mailbox store not confirmed (msg_id={:?}) — keeping pending", message_id);
                                }
                            }
                            P2PEvent::PendingUndeliverable { peer_id, message_id, reason } => {
                                // F12/F14: permanent failure — drop the pending
                                // row (scoped) and tell the UI the message is
                                // undeliverable instead of retrying forever.
                                log::warn!("Pending message to {} undeliverable: {}", peer_id, reason);
                                let app_state = handle.state::<AppState>();
                                let db_state = app_state.db.lock().await;
                                if let (Some(db), Some(id)) = (db_state.as_ref(), message_id.as_ref()) {
                                    if let Err(e) = db.delete_pending_message_by_id(&peer_id, id).await {
                                        log::warn!("Failed to delete undeliverable pending {}: {}", id, e);
                                    }
                                }
                                drop(db_state);
                                safe_emit(&handle, "message-failed", serde_json::json!({
                                    "to": peer_id,
                                    "error": reason,
                                }));
                            }
                            P2PEvent::MailboxError { error } => {
                                log::error!("Mailbox error: {}", error);
                            }
                            // D18: the mailbox resolver produced nothing —
                            // pending rows stay queued for the retry tick.
                            // No UI event needed; the log is the audit trail.
                            P2PEvent::MailboxNodeNotFound { peer_id } => {
                                log::debug!("No mailbox node resolved for peer {}", peer_id);
                            }
                            P2PEvent::MailboxNodeFound { peer_id, mailbox_peer_id, relay_addr } => {
                                log::debug!("Mailbox node found for {}: mailbox_peer={}, relay={}", peer_id, mailbox_peer_id, relay_addr);
                                let app_state = handle.state::<AppState>();
                                let my_id = app_state.my_id.lock().await.clone();

                                if mailbox_peer_id == my_id && peer_id != my_id {
                                    // MD-05: the peer's record resolves to OUR
                                    // node as the mailbox — storing locally
                                    // keeps delivery working instead of
                                    // silently dropping the envelopes.
                                    let db = app_state.db.lock().await.clone();
                                    let sessions = app_state.ratchet_sessions.clone();
                                    let security = app_state.security.clone();
                                    let dht_cipher = app_state.dht_cipher.lock()
                                        .map(|g| g.clone())
                                        .unwrap_or_else(|e| {
                                            log::error!("dht_cipher lock poisoned: {}", e);
                                            None
                                        });
                                    let my_id_clone = my_id.clone();
                                    let peer_id_clone = peer_id.clone();
                                    tokio::spawn(async move {
                                        if let Some(db) = db {
                                            if let Ok(pending) = db.get_pending_messages(&peer_id_clone).await {
                                                for (_row_id, raw_content, msg_id) in pending {
                                                    let Some(content) = decode_pending_content(&security, &raw_content).await else {
                                                        continue;
                                                    };
                                                    let encrypted_content: Option<Vec<u8>> = if content.starts_with("NOIDMSG1:") {
                                                        if let Ok(m) = serde_json::from_str::<crate::p2p::NoidMessage>(content.trim_start_matches("NOIDMSG1:")) {
                                                            if let crate::p2p::MessageType::RatchetChat { ciphertext, header_dh_public, header_pn, header_n } = &m.msg_type {
                                                                serde_json::to_vec(&crate::security::RatchetMessage {
                                                                    header: crate::security::RatchetHeader {
                                                                        dh_public: header_dh_public.clone(),
                                                                        pn: *header_pn,
                                                                        n: *header_n,
                                                                    },
                                                                    ciphertext: ciphertext.clone(),
                                                                }).ok()
                                                            } else { None }
                                                        } else { None }
                                                    } else {
                                                        match sessions.encrypt(&peer_id_clone, content.as_bytes()).await {
                                                            Ok(Some(rm)) => serde_json::to_vec(&rm).ok(),
                                                            _ => {
                                                                let key_opt = db.get_contact_public_key(&peer_id_clone).await.ok().flatten();
                                                                match (dht_cipher.as_ref(), key_opt) {
                                                                    (Some(cipher), Some(key)) if key.len() == 32 => {
                                                                        let mut kb = [0u8; 32];
                                                                        kb.copy_from_slice(&key);
                                                                        cipher.encrypt_for_recipient(
                                                                            content.as_bytes(),
                                                                            &x25519_dalek::PublicKey::from(kb),
                                                                        ).ok().and_then(|m| serde_json::to_vec(&m).ok())
                                                                    }
                                                                    _ => None,
                                                                }
                                                            }
                                                        }
                                                    };
                                                    if let Some(enc) = encrypted_content {
                                                        let expires = (chrono::Utc::now() + chrono::Duration::days(7))
                                                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                                        if db.store_mailbox_message(
                                                            &msg_id, &peer_id_clone, &my_id_clone, &enc, &expires, &[],
                                                        ).await.is_ok() {
                                                            let _ = db.delete_pending_message_by_id(&peer_id_clone, &msg_id).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });
                                } else {
                                    // F1: seed the mailbox peer's addr from the
                                    // verified record — store/retrieve/ack used
                                    // to rely on the peer cache alone and
                                    // stalled forever on unknown mailboxes.
                                    if !mailbox_peer_id.is_empty() && !relay_addr.is_empty() {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SeedPeerAddr {
                                                peer_id: mailbox_peer_id.clone(),
                                                addr: relay_addr.clone(),
                                            }).await;
                                        }
                                    }
                                }
                                if mailbox_peer_id == my_id {
                                    // handled above
                                } else if peer_id == my_id {
                                    // Phase I: This is OUR mailbox — retrieve stored messages
                                    if !mailbox_peer_id.is_empty() {
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::RetrieveFromMailbox {
                                                mailbox_peer_id: mailbox_peer_id.clone(),
                                                recipient_peer_id: my_id.clone(),
                                            }).await;
                                            log::debug!("Requested mailbox retrieval from {} for self", mailbox_peer_id);
                                        }
                                    }
                                } else {
                                    // This is someone else's mailbox — send our pending messages to it.
                                    if mailbox_peer_id.is_empty() {
                                        log::warn!("Mailbox node found for {} but no mailbox_peer_id — cannot send", peer_id);
                                        continue;
                                    }
                                    let db = app_state.db.clone();
                                    let sessions = app_state.ratchet_sessions.clone();
                                    let p2p_tx = app_state.p2p_tx.clone();
                                    let security = app_state.security.clone();
                                    let dht_cipher = app_state.dht_cipher.lock()
                                        .map(|g| g.clone())
                                        .unwrap_or_else(|e| {
                                            log::error!("dht_cipher lock poisoned: {}", e);
                                            None
                                        });
                                    let my_id_clone = my_id.clone();
                                    let mailbox_peer_id_clone = mailbox_peer_id.clone();
                                    let peer_id_clone = peer_id.clone();
                                    tokio::spawn(async move {
                                        // RC2: snapshot Database — decode_pending_content
                                        // locks `security` inside the loop.
                                        let db = db.lock().await.clone();
                                        if let Some(db) = db {
                                            if let Ok(pending) = db.get_pending_messages(&peer_id_clone).await {
                                                // get_pending_messages returns (id, content, message_id).
                                                for (_row_id, raw_content, msg_id) in pending {
                                                    let Some(content) = decode_pending_content(&security, &raw_content).await else {
                                                        log::warn!("Skipping undecryptable pending row for mailbox {}", peer_id_clone);
                                                        continue;
                                                    };
                                                    // MD-01: NOIDMSG1: payloads carry their own
                                                    // wire format — a RatchetChat row is already a
                                                    // serialized RatchetMessage (re-encrypting it
                                                    // advances the chain for nothing), and an
                                                    // X3DHInit must NEVER ride the session it
                                                    // bootstraps (chicken-and-egg: the receiver
                                                    // cannot decrypt the init that creates the
                                                    // session). Typed payloads go through the
                                                    // ECDH envelope; plain content uses ratchet
                                                    // when a session exists.
                                                    let encrypted_content: Option<Vec<u8>> = if let Some(json) = content.strip_prefix("NOIDMSG1:") {
                                                        match serde_json::from_str::<crate::p2p::NoidMessage>(json) {
                                                            Ok(m) => match &m.msg_type {
                                                                crate::p2p::MessageType::RatchetChat { ciphertext, header_dh_public, header_pn, header_n } => {
                                                                    serde_json::to_vec(&crate::security::RatchetMessage {
                                                                        header: crate::security::RatchetHeader {
                                                                            dh_public: header_dh_public.clone(),
                                                                            pn: *header_pn,
                                                                            n: *header_n,
                                                                        },
                                                                        ciphertext: ciphertext.clone(),
                                                                    }).ok()
                                                                }
                                                                _ => {
                                                                    let key_opt = db.get_contact_public_key(&peer_id_clone).await.ok().flatten();
                                                                    match (dht_cipher.as_ref(), key_opt) {
                                                                        (Some(cipher), Some(key)) if key.len() == 32 => {
                                                                            let mut kb = [0u8; 32];
                                                                            kb.copy_from_slice(&key);
                                                                            let recip = x25519_dalek::PublicKey::from(kb);
                                                                            cipher
                                                                                .encrypt_for_recipient(content.as_bytes(), &recip)
                                                                                .ok()
                                                                                .and_then(|m| serde_json::to_vec(&m).ok())
                                                                        }
                                                                        _ => {
                                                                            log::warn!("No DHT key for typed mailbox payload to {} — keeping pending", peer_id_clone);
                                                                            None
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            Err(_) => {
                                                                log::warn!("Corrupt NOIDMSG1 pending row for {} — keeping", peer_id_clone);
                                                                None
                                                            }
                                                        }
                                                    } else {
                                                        match sessions.encrypt(&peer_id_clone, content.as_bytes()).await {
                                                            Ok(Some(ratchet_msg)) => serde_json::to_vec(&ratchet_msg).ok(),
                                                            _ => {
                                                                let key_opt = db.get_contact_public_key(&peer_id_clone).await.ok().flatten();
                                                                match (dht_cipher.as_ref(), key_opt) {
                                                                    (Some(cipher), Some(key)) if key.len() == 32 => {
                                                                        let mut kb = [0u8; 32];
                                                                        kb.copy_from_slice(&key);
                                                                        let recip = x25519_dalek::PublicKey::from(kb);
                                                                        cipher
                                                                            .encrypt_for_recipient(content.as_bytes(), &recip)
                                                                            .ok()
                                                                            .and_then(|m| serde_json::to_vec(&m).ok())
                                                                    }
                                                                    _ => {
                                                                        log::warn!("No ratchet session or DHT key for {} — keeping pending", peer_id_clone);
                                                                        None
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    };
                                                    let Some(encrypted_content) = encrypted_content else {
                                                        log::warn!("Envelope encryption failed for {} — not sending to mailbox", peer_id_clone);
                                                        continue;
                                                    };
                                                    if let Some(tx) = crate::p2p_sender(&p2p_tx) {
                                                        // The pending row is NOT deleted here — only a real
                                                        // MailboxStoreAck confirms the store. Deleting on
                                                        // channel-send used to lose messages whenever the
                                                        // dial to the mailbox node failed.
                                                        let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendToMailbox {
                                                            mailbox_peer_id: mailbox_peer_id_clone.clone(),
                                                            recipient_peer_id: peer_id_clone.clone(),
                                                            sender_peer_id: my_id_clone.clone(),
                                                            encrypted_content,
                                                            client_msg_id: Some(msg_id),
                                                        }).await;
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                            P2PEvent::RelayStatusChanged { status } => {
                                if last_relay_status.as_ref() == Some(&status) {
                                    continue;
                                }
                                log::info!(
                                    "relay-status → UI: peers={} relays={} reservations={} addrs={:?}",
                                    status.peers_connected,
                                    status.known_relays,
                                    status.active_reservations,
                                    status.relayed_addrs
                                );
                                let app_state = handle.state::<AppState>();
                                *app_state.relay_status.lock().await = status.clone();
                                safe_emit(&handle, "relay-status", status.clone());
                                last_relay_status = Some(status);
                            }
                        }
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
            commands::get_relay_status,
            commands::get_relay_config,
            commands::set_node_role,
            commands::set_privacy_mode,
            commands::send_contact_request,
            commands::connect_to_addr,
            commands::get_my_invite,
            commands::accept_contact_request,
            commands::deny_contact_request,
            commands::get_contacts,
            commands::get_contact_requests,
            commands::send_read_receipt,
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
