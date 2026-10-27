//! Phase 3.5: Ratchet session manager
//!
//! Manages X3DH handshakes and Double Ratchet sessions for E2EE.
//! Sessions are cached in memory and persisted to the database.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::db::Database;
use crate::security::ratchet::{DoubleRatchet, RatchetMessage};
use crate::security::x3dh::{X3DH, InitialMessage, PrekeyBundle};

/// Manages E2EE sessions per peer
pub struct RatchetSessionManager {
    /// In-memory cache of active ratchet sessions, keyed by peer_id
    sessions: Mutex<HashMap<String, DoubleRatchet>>,
    /// Our X3DH identity
    identity: Mutex<X3DH>,
    /// Consecutive decrypt failures per peer — persistent failures mean the
    /// peers' ratchet states have diverged (e.g. an X3DH init computed a
    /// different shared secret) and only a fresh handshake recovers them.
    decrypt_failures: Mutex<HashMap<String, u32>>,
    /// Rate limit for auto re-handshakes — one per peer per 5 minutes so two
    /// desynced peers cannot loop X3DHInit storms at each other.
    last_rehandshake: Mutex<HashMap<String, std::time::Instant>>,
    /// CR-01: per-peer serialization for export+persist — two concurrent
    /// saves otherwise interleave export(A1)→export(A2)→write(A2)→write(A1)
    /// and the STALE snapshot overwrites the newer chain state, permanently
    /// desyncing the pair.
    save_locks: Mutex<HashMap<String, std::sync::Arc<Mutex<()>>>>,
}

impl RatchetSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            identity: Mutex::new(X3DH::new()),
            decrypt_failures: Mutex::new(HashMap::new()),
            last_rehandshake: Mutex::new(HashMap::new()),
            save_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Phase A.2: Initialize from database — loads or creates identity key.
    pub async fn init_from_db(db: &Database) -> Result<Self> {
        let identity = if let Some((_pub_bytes, priv_bytes)) = db.get_identity_key().await? {
            let secret_bytes: [u8; 32] = priv_bytes.as_slice().try_into()
                .map_err(|_| anyhow!("Invalid identity key length in DB"))?;
            let secret = x25519_dalek::StaticSecret::from(secret_bytes);
            log::info!("Loaded X3DH identity key from database");
            X3DH::from_secret(secret)
        } else {
            let x3dh = X3DH::new();
            db.save_identity_key(&x3dh.identity_public_bytes(), &x3dh.identity_secret_bytes()).await?;
            log::info!("Generated and saved new X3DH identity key");
            x3dh
        };
        Ok(Self {
            sessions: Mutex::new(HashMap::new()),
            identity: Mutex::new(identity),
            decrypt_failures: Mutex::new(HashMap::new()),
            last_rehandshake: Mutex::new(HashMap::new()),
            save_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Get our identity public key bytes for sharing with contacts
    pub async fn identity_public_bytes(&self) -> Vec<u8> {
        self.identity.lock().await.identity_public_bytes()
    }

    /// Phase A.2: Load or create identity from DB. Called after login when DB is available.
    pub async fn load_identity_from_db(&self, db: &Database) -> Result<()> {
        let identity = if let Some((_pub_bytes, priv_bytes)) = db.get_identity_key().await? {
            let secret_bytes: [u8; 32] = priv_bytes.as_slice().try_into()
                .map_err(|_| anyhow!("Invalid identity key length in DB"))?;
            let secret = x25519_dalek::StaticSecret::from(secret_bytes);
            log::info!("Loaded X3DH identity key from database");
            X3DH::from_secret(secret)
        } else {
            let x3dh = X3DH::new();
            db.save_identity_key(&x3dh.identity_public_bytes(), &x3dh.identity_secret_bytes()).await?;
            log::info!("Generated and saved new X3DH identity key");
            x3dh
        };
        *self.identity.lock().await = identity;
        Ok(())
    }

    /// Phase A.3: Generate prekeys and store them in the database.
    /// Returns a PrekeyBundle suitable for publishing to DHT.
    pub async fn generate_and_store_prekeys(&self, db: &Database) -> Result<PrekeyBundle> {
        let identity = self.identity.lock().await;
        let identity_public = identity.identity_public_bytes();

        // 1. Load or generate signed prekey
        let (spk_pub, _spk_priv) = match db.get_signed_prekey().await? {
            Some((p, s)) => {
                log::debug!("Loaded existing signed prekey from DB");
                (p, s)
            }
            None => {
                // Generate key material BEFORE any await — ThreadRng is not Send
                let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                let public = x25519_dalek::PublicKey::from(&secret);
                let pub_bytes = public.to_bytes().to_vec();
                let priv_bytes = secret.to_bytes().to_vec();
                db.save_signed_prekey(&pub_bytes, &priv_bytes).await?;
                log::info!("Generated and saved new signed prekey");
                (pub_bytes, priv_bytes)
            }
        };

        // 2. S1: maintain a POOL of OTPKs — a single advertised key meant
        // one stale init burned the only key and fail-closed the node.
        // Top up to 10, advertise all of them; legacy `one_time_prekey_public`
        // mirrors the first pool entry for old peers.
        let mut otpk_count = db.get_one_time_prekey_count().await?;
        while otpk_count < 10 {
            // Generate key material BEFORE any await — ThreadRng is not Send
            let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            let public = x25519_dalek::PublicKey::from(&secret);
            let pub_bytes = public.to_bytes().to_vec();
            let priv_bytes = secret.to_bytes().to_vec();
            db.add_one_time_prekey(&pub_bytes, &priv_bytes).await?;
            otpk_count += 1;
        }
        let one_time_prekeys = db.get_available_one_time_prekey_pubs(10).await?;
        let one_time_prekey_public = one_time_prekeys.first().cloned();

        Ok(PrekeyBundle {
            identity_public,
            signed_prekey_public: spk_pub,
            one_time_prekey_public,
            one_time_prekeys,
            owner_peer_id: None,
            identity_signature: None,
            generated_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        })
    }

    /// Initiate X3DH handshake with a peer using their prekey bundle.
    /// Returns the initial message to send and establishes a ratchet session.
    pub async fn initiate_session(
        &self,
        peer_id: &str,
        bundle: &PrekeyBundle,
    ) -> Result<InitialMessage> {
        // D17: reject signed-but-stale bundles — a replayed ancient record
        // advertises OTPKs we no longer hold, so the handshake fail-closes
        // on the bob side and the pair can never establish a session.
        if let Some(ts) = &bundle.generated_at {
            if let Ok(generated) = chrono::DateTime::parse_from_rfc3339(ts) {
                let age = chrono::Utc::now() - generated.with_timezone(&chrono::Utc);
                if age > chrono::Duration::hours(48) {
                    return Err(anyhow!(
                        "Stale prekey bundle for {} ({}h old) — refusing to initiate",
                        peer_id,
                        age.num_hours()
                    ));
                }
            }
        }
        let identity = self.identity.lock().await;
        let (initial_msg, shared_secret) = identity.initiate(bundle)?;

        // The peer's signed prekey public key becomes the remote public key for Alice's ratchet
        let signed_prekey_bytes: [u8; 32] = bundle.signed_prekey_public.as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid signed prekey length"))?;
        let peer_signed_prekey = x25519_dalek::PublicKey::from(signed_prekey_bytes);

        let ratchet = DoubleRatchet::init_alice(shared_secret, peer_signed_prekey)?;

        let mut sessions = self.sessions.lock().await;
        sessions.insert(peer_id.to_string(), ratchet);

        Ok(initial_msg)
    }

    /// Receive X3DH handshake from a peer.
    /// Called when we receive an X3DHInit message.
    pub async fn receive_session(
        &self,
        peer_id: &str,
        initial_msg: &InitialMessage,
        signed_prekey_secret: &x25519_dalek::StaticSecret,
        one_time_prekey_secret: Option<&x25519_dalek::StaticSecret>,
    ) -> Result<()> {
        let identity = self.identity.lock().await;
        let shared_secret = identity.receive(initial_msg, signed_prekey_secret, one_time_prekey_secret)?;

        let ratchet = DoubleRatchet::init_bob(shared_secret, signed_prekey_secret.clone());

        let mut sessions = self.sessions.lock().await;
        sessions.insert(peer_id.to_string(), ratchet);

        Ok(())
    }

    /// Encrypt a message for a peer using the established ratchet session.
    /// Returns None if no session exists (caller should fall back to plaintext).
    pub async fn encrypt(&self, peer_id: &str, plaintext: &[u8]) -> Result<Option<RatchetMessage>> {
        let mut sessions = self.sessions.lock().await;
        if let Some(ratchet) = sessions.get_mut(peer_id) {
            let msg = ratchet.encrypt(plaintext)?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Decrypt a ratchet message from a peer.
    pub async fn decrypt(&self, peer_id: &str, message: &RatchetMessage) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.lock().await;
        if let Some(ratchet) = sessions.get_mut(peer_id) {
            ratchet.decrypt(message)
        } else {
            Err(anyhow!("No ratchet session with {}", peer_id))
        }
    }

    /// Check if a session exists for a peer
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.lock().await.contains_key(peer_id)
    }

    /// MD-03: true once the peer has answered on this session. An
    /// unconfirmed outgoing (Alice) session still accepts a concurrent
    /// X3DHInit — that is the handshake-glare tie-break, not a resync need.
    pub async fn is_confirmed(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .await
            .get(peer_id)
            .map(|s| s.is_confirmed())
            .unwrap_or(false)
    }

    /// Count a decrypt failure for `peer_id` — returns the consecutive count.
    pub async fn record_decrypt_failure(&self, peer_id: &str) -> u32 {
        let mut map = self.decrypt_failures.lock().await;
        let n = map.get(peer_id).copied().unwrap_or(0) + 1;
        map.insert(peer_id.to_string(), n);
        n
    }

    /// S5: true when `msg` replays an already-consumed ratchet position —
    /// AEAD failure there is expected and must not feed the desync counter.
    pub async fn is_replay_message(
        &self,
        peer_id: &str,
        msg: &crate::security::RatchetMessage,
    ) -> bool {
        let sessions = self.sessions.lock().await;
        sessions
            .get(peer_id)
            .map(|s| s.is_replay_header(&msg.header))
            .unwrap_or(false)
    }

    /// Reset the failure counter — called on any successful decrypt.
    pub async fn note_decrypt_success(&self, peer_id: &str) {
        self.decrypt_failures.lock().await.remove(peer_id);
    }

    /// Pure desync predicate — the session failed ≥3 consecutive decrypts.
    /// Unlike `should_rehandshake` it neither rate-limits nor marks an
    /// attempt, so an inbound X3DHInit is never suppressed by OUR outbound
    /// re-handshake bookkeeping (CR-05: `should_rehandshake` in the inbound
    /// gate wrote `last_rehandshake` and then rejected the peer's init for
    /// 5 minutes — a self-inflicted deadlock after desync).
    pub async fn is_desynced(&self, peer_id: &str) -> bool {
        self.decrypt_failures
            .lock()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or(0)
            >= 3
    }

    /// True when a fresh X3DH handshake should be attempted: the session has
    /// failed to decrypt ≥3 consecutive messages AND no re-handshake was
    /// triggered for this peer in the last 5 minutes (marks the attempt).
    /// Outbound trigger only — never gate inbound X3DHInit on this.
    pub async fn should_rehandshake(&self, peer_id: &str) -> bool {
        let failures = self.decrypt_failures.lock().await.get(peer_id).copied().unwrap_or(0);
        if failures < 3 {
            return false;
        }
        let mut last = self.last_rehandshake.lock().await;
        let now = std::time::Instant::now();
        if last
            .get(peer_id)
            .map(|t| now.duration_since(*t) < std::time::Duration::from_secs(300))
            .unwrap_or(false)
        {
            return false;
        }
        last.insert(peer_id.to_string(), now);
        true
    }

    /// Drop the ratchet session and failure bookkeeping for a peer — used when
    /// replacing a desynced session via a fresh X3DH handshake.
    pub async fn drop_session(&self, peer_id: &str) {
        self.sessions.lock().await.remove(peer_id);
        self.decrypt_failures.lock().await.remove(peer_id);
        self.save_locks.lock().await.remove(peer_id);
    }

    /// Drop every ratchet session and the in-memory X3DH identity — used on
    /// KillPin wipe so a subsequent login cannot reuse stale key material.
    pub async fn clear_all(&self) {
        self.sessions.lock().await.clear();
        self.decrypt_failures.lock().await.clear();
        self.last_rehandshake.lock().await.clear();
        self.save_locks.lock().await.clear();
        *self.identity.lock().await = X3DH::new();
    }

    /// Persist a session state to the database. RC23: the sessions lock is
    /// released BEFORE the db await — holding it through the SQL call stalled
    /// every concurrent encrypt/decrypt behind one disk write.
    /// CR-01: a per-peer save lock serializes export→write, so two concurrent
    /// saves cannot commit an older snapshot over a newer chain state.
    pub async fn save_session(&self, db: &Database, peer_id: &str) -> Result<()> {
        let save_lock = {
            let mut locks = self.save_locks.lock().await;
            locks
                .entry(peer_id.to_string())
                .or_insert_with(|| std::sync::Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = save_lock.lock().await;
        let state = {
            let sessions = self.sessions.lock().await;
            sessions.get(peer_id).map(|ratchet| ratchet.export_state())
        };
        if let Some(state) = state {
            db.save_ratchet_state(peer_id, &state).await?;
        }
        Ok(())
    }

    /// Phase A.6: Load a session state from the database and restore it.
    pub async fn load_session(&self, db: &Database, peer_id: &str) -> Result<bool> {
        if let Some(state) = db.get_ratchet_state(peer_id).await? {
            let ratchet = DoubleRatchet::import_state(&state)?;
            self.sessions.lock().await.insert(peer_id.to_string(), ratchet);
            log::info!("Restored ratchet session for {} ({} bytes)", peer_id, state.len());
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for RatchetSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
