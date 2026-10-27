use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use rand::RngCore;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Security audit log.
///
/// Lines written BEFORE the master key is attached (login attempts, KillPin)
/// stay plaintext — they carry no peer or message metadata. Once `set_key`
/// runs at unlock, the details column is AES-256-GCM encrypted
/// (`enc1:` + base64(nonce || ciphertext)) so peer ids and message ids are
/// not readable at rest by anyone who cannot derive the PIN key.
enum AuditMsg {
    Line(String),
    Flush(std::sync::mpsc::Sender<()>),
}

pub struct AuditLog {
    key: Mutex<Option<[u8; 32]>>,
    /// RC24: a single writer thread drains formatted lines — callers on the
    /// async runtime never block on file IO, and ordering stays FIFO.
    writer: Mutex<Option<std::sync::mpsc::Sender<AuditMsg>>>,
    log_path: PathBuf,
}

impl AuditLog {
    pub fn new(data_dir: &std::path::Path) -> Self {
        let log_path = data_dir.join("audit.log");
        Self {
            key: Mutex::new(None),
            writer: Mutex::new(None),
            log_path,
        }
    }

    /// Lazily start the writer thread; returns the line sender.
    fn writer_tx(&self) -> Result<std::sync::mpsc::Sender<AuditMsg>> {
        let mut guard = self
            .writer
            .lock()
            .map_err(|_| anyhow!("audit log writer mutex poisoned"))?;
        if let Some(tx) = guard.as_ref() {
            return Ok(tx.clone());
        }
        let (tx, rx) = std::sync::mpsc::channel::<AuditMsg>();
        let path = self.log_path.clone();
        std::thread::Builder::new()
            .name("audit-log-writer".into())
            .spawn(move || {
                // DB26: size-bounded append — rotates audit.log → .1 → .2
                // past 10 MiB instead of growing forever. The handle is
                // kept open for the thread's lifetime (no open per line).
                let mut out = match crate::util::rotating_log::RotatingLog::open(&path) {
                    Ok(l) => Some(l),
                    Err(e) => {
                        log::warn!("audit log open failed: {}", e);
                        None
                    }
                };
                while let Ok(msg) = rx.recv() {
                    match msg {
                        AuditMsg::Line(line) => {
                            if let Some(ref mut l) = out {
                                if let Err(e) = l.write_all(line.as_bytes()) {
                                    log::warn!("audit log write failed: {}", e);
                                }
                            }
                        }
                        AuditMsg::Flush(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            })
            .map_err(|e| anyhow!("audit writer thread spawn: {}", e))?;
        *guard = Some(tx.clone());
        Ok(tx)
    }

    /// Wait until every line logged so far has hit the disk. Tests and the
    /// shutdown path use this before reading/exiting.
    pub fn flush(&self) -> Result<()> {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        self.writer_tx()?
            .send(AuditMsg::Flush(ack_tx))
            .map_err(|_| anyhow!("audit log writer dead"))?;
        ack_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| anyhow!("audit log flush timeout: {}", e))
    }

    /// Attach the PIN-derived master key; the "audit" domain subkey is
    /// derived from it (S14). All subsequent `details` payloads are
    /// encrypted at rest. Called once from the login/setup path.
    pub fn set_key(&self, key: [u8; 32]) {
        if let Ok(mut guard) = self.key.lock() {
            *guard = Some(crate::security::derive_domain_key(&key, "audit"));
        }
    }

    /// Encrypt `details` when a key is attached; returns the payload column.
    fn seal(&self, details: &str) -> Result<String> {
        let key = self
            .key
            .lock()
            .map_err(|_| anyhow!("audit log key mutex poisoned"))?;
        match *key {
            Some(k) => {
                let cipher = Aes256Gcm::new_from_slice(&k)
                    .map_err(|e| anyhow!("audit cipher init: {}", e))?;
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ct = cipher
                    .encrypt(Nonce::from_slice(&nonce), details.as_bytes())
                    .map_err(|e| anyhow!("audit seal failed: {}", e))?;
                let mut blob = nonce.to_vec();
                blob.extend_from_slice(&ct);
                Ok(format!(
                    "enc2:{}",
                    base64::engine::general_purpose::STANDARD.encode(&blob)
                ))
            }
            None => Ok(details.to_string()),
        }
    }

    pub fn log(&self, event: &str, details: &str) -> Result<()> {
        let payload = self.seal(details)?;
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let line = format!("[{}] {} | {}\n", timestamp, event, payload);
        self.writer_tx()?
            .send(AuditMsg::Line(line))
            .map_err(|_| anyhow!("audit log writer dead"))?;
        Ok(())
    }

    pub fn log_login(&self, success: bool) -> Result<()> {
        self.log("AUTH", if success { "Login successful" } else { "Login failed" })
    }

    pub fn log_kill_pin(&self) -> Result<()> {
        self.log("SECURITY", "Kill PIN activated — data wiped")
    }

    pub fn log_key_exchange(&self, peer_id: &str) -> Result<()> {
        self.log("KEY_EXCHANGE", &format!("Public key exchanged with peer {}", peer_id))
    }

    pub fn log_dht_store(&self, peer_id: &str) -> Result<()> {
        self.log("DHT_STORE", &format!("Message stored in DHT for peer {}", peer_id))
    }

    pub fn log_dht_retrieve(&self, peer_id: &str) -> Result<()> {
        self.log("DHT_RETRIEVE", &format!("Message retrieved from DHT from peer {}", peer_id))
    }

    pub fn log_replay_detected(&self, msg_id: &str) -> Result<()> {
        self.log("REPLAY", &format!("Duplicate message detected: {}", msg_id))
    }

    pub fn log_screenshot_protection(&self, enabled: bool) -> Result<()> {
        self.log("SCREENSHOT", if enabled { "Protection enabled" } else { "Protection disabled" })
    }
}
