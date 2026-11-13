//! Application state — `AppState` and its helpers (gate, senders, uniform
//! DB/P2P guards). Extracted from lib.rs (Q05/A5b); bodies moved verbatim.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::db::Database;
use crate::auth;
use crate::security::SecurityManager;

/// Consented inbound file offers: "<sender>:<offer_id>" → (sender, name, size).
type PendingFileOffers = Arc<Mutex<HashMap<String, (String, String, u64)>>>;

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
    /// Persisted connectivity policy (on-demand vs persistent conns,
    /// idle TTL, ping/poll intervals).
    pub connectivity_config: Arc<Mutex<crate::p2p::connectivity_config::ConnectivityConfig>>,
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
    /// P3: network-layer generation bumped on every Tor/mode reconfigure
    /// that recreates the P2P node — deliberately separate from
    /// `login_epoch` (a mode change must NOT wipe identity, contacts or
    /// ratchet state).
    pub network_generation: Arc<std::sync::atomic::AtomicU64>,
    /// App log directory (tauri-plugin-log target) — wiped by KillPin so
    /// no message ids / peer ids survive in noid.log.
    pub app_log_dir: PathBuf,
    /// F11: peers with a live connection — fed by PeerConnected /
    /// PeerDisconnected so the pending-retry loop can flush directly
    /// instead of waiting for the mailbox cycle.
    pub connected_peers: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Active one-time invite rendezvous secret — `get_my_invite` reuses it
    /// inside a 20-min window instead of minting (and invalidating) a fresh
    /// `?rv=` on every UI refresh. Cleared on wipe with the rest.
    pub invite_rv: Arc<Mutex<Option<(String, std::time::Instant)>>>,
    /// TI-15: inbound file reassembly — keyed `from:offer_id`, entries hold
    /// received chunks until `total_chunks` arrives (then the file is
    /// written to `<app_data>/received/`). Bounded + TTL'd against
    /// abandoned transfers.
    pub file_inbox:
        Arc<Mutex<HashMap<String, crate::file_inbox::FileInboxEntry>>>,
    /// SEC-1111-06: offers awaiting explicit user consent — key is
    /// "<sender>:<offer_id>", value (sender, name, size). Only a consented
    /// key is promoted into `file_inbox` via `accept_file_offer`; chunks
    /// without consent are dropped.
    pub pending_file_offers: PendingFileOffers,
    /// Embedded Tor lifecycle handle: identity/status/supervisor. Reports
    /// `Unsupported` when built without `embedded-tor` or under
    /// `NOID_DISABLE_TOR=1`; never starts Tor without consent.
    pub tor: crate::p2p::tor::handle::TorHandle,
    /// SEC-A01: detached network writers (RequestReceived/RoomMessage
    /// handlers, inbound retry workers) register their JoinHandle here so
    /// KillPin can cancel-and-join them — a fixed sleep never proved
    /// quiescence.
    pub session_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// A1: the live session opened the decoy profile (`cache/` root)
    /// rather than the real one. Set by `login` BEFORE the gate opens —
    /// the node supervisor reads it at incarnation start and builds the
    /// node against the decoy key store, so a decoy session never touches
    /// the real identity.
    pub is_decoy: std::sync::atomic::AtomicBool,
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

/// SEC-A01: register a detached task in the session writer registry —
/// KillPin drains this set so no writer outlives revocation. Finished
/// handles are compacted on registration.
pub async fn track_task(app: &tauri::AppHandle, handle: tokio::task::JoinHandle<()>) {
    let state = app.state::<AppState>();
    let mut tasks = state.session_tasks.lock().await;
    tasks.retain(|h| !h.is_finished());
    tasks.push(handle);
}

/// SEC-A01: cancel every registered session writer and await termination,
/// bounded. After this returns, no tracked task may still hold a DB/Tor
/// clone — the wipe may proceed to pool close and filesystem erase.
pub async fn drain_session_tasks(app_state: &AppState, timeout: Duration) {
    let drained: Vec<tokio::task::JoinHandle<()>> = {
        let mut tasks = app_state.session_tasks.lock().await;
        std::mem::take(&mut *tasks)
    };
    for h in &drained {
        h.abort();
    }
    let _ = tokio::time::timeout(timeout, async move {
        for h in drained {
            let _ = h.await;
        }
    })
    .await;
}

/// OPT-R03: the confirmed-wipe pipeline, shared by kill_switch and the
/// KillPin branch of login — revoke order must stay: admission stops
/// (epoch + gate), Tor generation + identity are revoked, tracked session
/// writers are joined, in-memory plaintext is dropped, the DB pool closes,
/// then blocking erase + log-dir wipe. Both call sites used to keep two
/// hand-synced copies of this sequence.
pub(crate) async fn run_wipe_workflow(app_state: &AppState) -> Result<(), String> {
    // SEC-1111-09: no "kill pin used" record hits the disk — the barrier
    // is flush + writer shutdown + key zeroize, not a log line that a
    // partial-wipe failure could leave behind.
    app_state.audit_log.shutdown_and_zeroize();
    app_state.login_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    gate_set(&app_state.p2p_start_tx, false);
    if let Err(e) = app_state.tor.revoke().await {
        log::error!("Tor revoke before wipe failed: {}", e);
    }
    drain_session_tasks(app_state, Duration::from_secs(5)).await;
    // RUN-A02: decrypted inbound chunks must not survive the wipe in RAM.
    app_state.file_inbox.lock().await.clear();
    // Pool close AFTER writers are joined — clones held by aborted tasks
    // are released with them.
    {
        let mut db_state = app_state.db.lock().await;
        *db_state = None;
    }
    log::info!("Database pool closed before wipe");

    // Give released pools a moment so secure_delete does not hit file
    // locks on Windows.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // RC15: secure_delete is synchronous fs work — off the executor.
    let security_arc = app_state.security.clone();
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

    // noid.log may contain peer ids, message ids and network addresses.
    let log_dir = app_state.app_log_dir.clone();
    if log_dir.exists() {
        if let Err(e) = crate::security::secure_delete::secure_delete_dir(&log_dir) {
            log::error!("Log dir wipe failed: {}", e);
        }
    }
    Ok(())
}

/// Set the P2P gate desired-state, bumping `seq` unconditionally.
pub fn gate_set(tx: &tokio::sync::watch::Sender<P2PGate>, open: bool) {
    log::info!("gate_set(open={})", open);
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
    /// Root dir of the ACTIVE profile: `cache/` in a decoy session, the
    /// real `app_data_dir` otherwise. The node supervisor resolves this
    /// once per incarnation — per-profile artifacts (keys, peer cache,
    /// mailbox db, audit log) always live under it.
    pub fn profile_dir(&self) -> PathBuf {
        if self.is_decoy.load(std::sync::atomic::Ordering::Relaxed) {
            self.app_data_dir
                .join(crate::security::decoy_vault::DECOY_DIR_NAME)
        } else {
            self.app_data_dir.clone()
        }
    }

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

