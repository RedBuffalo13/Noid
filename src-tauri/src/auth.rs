use std::sync::Arc;
use tokio::sync::Mutex;

const STATE_FILE: &str = "auth_state.json";

/// Failed attempts before the timed lockout engages (FE-03: surfaced to the
/// UI as `attempts_remaining`).
pub const LOCKOUT_THRESHOLD: u32 = 5;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PersistedAuth {
    failed_attempts: u32,
    /// Unix seconds of the most recent failure — the lockout decays
    /// instead of being permanent (S10).
    #[serde(default)]
    last_failed_ts: i64,
}

/// S10: lockout is a *timed* backoff, not a permanent ban. 5+ failures →
/// locked for `backoff_secs(attempts)`, doubling per extra failure.
/// The old "restart the app" state was a permanent self-DoS.
fn backoff_secs(attempts: u32) -> u64 {
    if attempts < 5 {
        return 0;
    }
    60u64
        .checked_shl(attempts.saturating_sub(5))
        .unwrap_or(u64::MAX)
        .min(3600)
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Brute-force lockout state. Persisted to `auth_state.json` so a restart
/// does NOT reset the counter — otherwise an attacker gets a fresh 5
/// attempts per app launch. The file lives in `data_dir`, so KillPin's
/// wipe removes it together with everything else.
pub struct AuthManager {
    pub failed_attempts: Arc<Mutex<u32>>,
    pub locked_out: Arc<Mutex<bool>>,
    state_path: Option<std::path::PathBuf>,
    last_failed_ts: Arc<Mutex<i64>>,
}

impl AuthManager {
    /// In-memory manager (tests / headless without a data dir).
    pub fn new() -> Self {
        Self {
            failed_attempts: Arc::new(Mutex::new(0)),
            locked_out: Arc::new(Mutex::new(false)),
            state_path: None,
            last_failed_ts: Arc::new(Mutex::new(0)),
        }
    }

    /// Load persisted lockout state, or start fresh.
    pub fn load(data_dir: &std::path::Path) -> Self {
        let state_path = data_dir.join(STATE_FILE);
        let persisted = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|s| serde_json::from_str::<PersistedAuth>(&s).ok())
            .unwrap_or_default();
        let attempts = persisted.failed_attempts;
        let locked = Self::locked(attempts, persisted.last_failed_ts);
        Self {
            failed_attempts: Arc::new(Mutex::new(attempts)),
            locked_out: Arc::new(Mutex::new(locked)),
            state_path: Some(state_path),
            last_failed_ts: Arc::new(Mutex::new(persisted.last_failed_ts)),
        }
    }

    /// Timed-lockout check: still locked iff attempts >= 5 AND the backoff
    /// window since the last failure has not elapsed.
    fn locked(attempts: u32, last_failed_ts: i64) -> bool {
        attempts >= 5
            && last_failed_ts > 0
            && (now_ts() - last_failed_ts) < backoff_secs(attempts) as i64
    }

    fn persist(&self, attempts: u32, last_failed_ts: i64) {
        if let Some(ref path) = self.state_path {
            if let Ok(json) = serde_json::to_vec(&PersistedAuth {
                failed_attempts: attempts,
                last_failed_ts,
            }) {
                if let Err(e) = std::fs::write(path, json) {
                    log::warn!("Failed to persist auth state: {}", e);
                }
            }
        }
    }

    fn clear_persisted(&self) {
        if let Some(ref path) = self.state_path {
            let _ = std::fs::remove_file(path);
        }
    }

    pub async fn increment_failed_attempt(&self) -> u32 {
        let ts = now_ts();
        let mut attempts = self.failed_attempts.lock().await;
        *attempts += 1;
        let count = *attempts;
        *self.last_failed_ts.lock().await = ts;

        if Self::locked(count, ts) {
            let mut locked = self.locked_out.lock().await;
            *locked = true;
        }
        drop(attempts);
        self.persist(count, ts);

        count
    }

    pub async fn reset_attempts(&self) {
        let mut attempts = self.failed_attempts.lock().await;
        *attempts = 0;
        *self.last_failed_ts.lock().await = 0;
        let mut locked = self.locked_out.lock().await;
        *locked = false;
        drop(attempts);
        drop(locked);
        self.clear_persisted();
    }

    /// Seconds until the lockout lifts (0 = not locked). Recomputes from
    /// the persisted timestamp — the stored `locked_out` flag goes stale
    /// across sleeps, so the flag is refreshed here as a side effect.
    pub async fn lockout_remaining_secs(&self) -> u64 {
        let attempts = *self.failed_attempts.lock().await;
        let last = *self.last_failed_ts.lock().await;
        let remaining = backoff_secs(attempts)
            .saturating_sub((now_ts() - last).max(0) as u64);
        if attempts < 5 || remaining == 0 {
            let mut locked = self.locked_out.lock().await;
            *locked = false;
            return 0;
        }
        remaining
    }

    pub async fn is_locked_out(&self) -> bool {
        self.lockout_remaining_secs().await > 0
    }

    /// S11: progressive delay for a failed secret attempt. The caller
    /// sleeps this BEFORE answering — brute force through the IPC boundary
    /// costs 2^n seconds per try (cap 64s; a correct PIN answers instantly).
    pub async fn failed_attempt_delay(&self) -> std::time::Duration {
        let attempts = *self.failed_attempts.lock().await;
        std::time::Duration::from_secs(1u64 << attempts.min(6))
    }

    pub async fn get_failed_attempts(&self) -> u32 {
        *self.failed_attempts.lock().await
    }
}
