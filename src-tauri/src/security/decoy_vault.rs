//! Decoy Vault (A1) — a second, innocuous profile behind a second PIN.
//!
//! Threat model: coercion. The user surrenders a PIN and opens the app —
//! a `decoy PIN` unlocks a plausible but harmless profile instead of the
//! real one. The decoy is a *separate profile root* (`<data_dir>/cache/`),
//! not a flag on the real DB: it carries its own salt, master key,
//! `noid.db`, node keys (`identity.key`, `dht.key`) and audit log, so the
//! real profile's key material and message history never enter a decoy
//! session.
//!
//! Naming is deliberately mundane (`cache/`): there is no cryptographically
//! provable deniability at the filesystem layer — the cover is that the
//! directory reads as an app-internal partition and is populated by
//! `decoy_seeder` to look like a lightly-used account. The decoy PIN hash
//! lives at `cache/verify.hash` (present only when the feature is
//! configured); `kill_everything` shreds the whole `data_dir`, so the
//! decoy root dies with the real one on ANY PIN-triggered wipe.

use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use std::fs;

use super::manager::SecurityManager;

/// Decoy profile root, relative to `data_dir`. Reads as an app-internal
/// cache partition; holds a full `noid.db` + node keys of its own.
pub const DECOY_DIR_NAME: &str = "cache";

impl SecurityManager {
    /// `<data_dir>/cache/` — the decoy profile root.
    pub fn decoy_dir(&self) -> std::path::PathBuf {
        self.data_dir.join(DECOY_DIR_NAME)
    }

    /// A decoy PIN exists only when `cache/verify.hash` was written.
    pub fn is_decoy_configured(&self) -> bool {
        self.decoy_dir().join("verify.hash").exists()
    }

    /// Store the decoy PIN verifier under hardened Argon2id — the same
    /// floor as `true_pin.hash`/`kill.hash`, so a swapped-in weak hash can
    /// never verify (SEC-1111-09 applies here too).
    pub fn save_decoy_pin_hash(&self, pin: &str) -> Result<()> {
        let dir = self.decoy_dir();
        fs::create_dir_all(&dir)?;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 1, None)
                .map_err(|e| anyhow!("Argon2 params error: {}", e))?,
        );
        let hash = argon2
            .hash_password(pin.as_bytes())
            .map_err(|e| anyhow!("KDF error: {}", e))?
            .to_string();
        fs::write(dir.join("verify.hash"), hash)?;
        Ok(())
    }

    /// `None` when no decoy PIN is configured; `Some(bool)` otherwise.
    /// Costs one Argon2 verify — the caller runs it in parallel with the
    /// true/kill checks so login latency reveals nothing about which slot
    /// matched.
    pub fn verify_decoy_pin(&self, pin: &str) -> Option<bool> {
        let hash_path = self.decoy_dir().join("verify.hash");
        if !hash_path.exists() {
            return None;
        }
        let hash_str = fs::read_to_string(hash_path).ok()?;
        let parsed_hash = PasswordHash::new(&hash_str).ok()?;
        match argon2::Params::try_from(&parsed_hash) {
            Ok(p) if p.m_cost() >= 65536 && p.t_cost() >= 3 => {}
            _ => return Some(false),
        }
        Some(
            Argon2::default()
                .verify_password(pin.as_bytes(), &parsed_hash)
                .is_ok(),
        )
    }

    /// Derive the decoy master key — Argon2id under `cache/salt.bin`,
    /// independent of the real `salt.bin`. First use mints the salt; the
    /// noid.db-without-salt corruption guard applies here as well.
    pub fn derive_decoy_key(&mut self, pin: &str) -> Result<()> {
        self.derive_key_in(pin, &self.decoy_dir())
    }

    /// Remove the decoy profile entirely (secure-delete the `cache` root).
    /// The real profile is untouched — this is NOT the wipe path; KillPin
    /// still shreds the whole `data_dir`.
    pub fn clear_decoy(&self) -> Result<()> {
        let dir = self.decoy_dir();
        if dir.exists() {
            crate::security::secure_delete::secure_delete_dir(&dir)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_decoy_verifies_none() {
        let dir = std::env::temp_dir().join(format!("noid-decoy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = SecurityManager::new(dir.clone());
        assert!(!mgr.is_decoy_configured());
        assert_eq!(mgr.verify_decoy_pin("anything"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoy_pin_roundtrip_and_wrong_rejected() {
        let dir = std::env::temp_dir().join(format!("noid-decoy2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = SecurityManager::new(dir.clone());
        mgr.save_decoy_pin_hash("decoy-pin-123").unwrap();
        assert!(mgr.is_decoy_configured());
        assert_eq!(mgr.verify_decoy_pin("decoy-pin-123"), Some(true));
        assert_eq!(mgr.verify_decoy_pin("wrong-pin-456"), Some(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoy_master_key_differs_from_true() {
        let dir = std::env::temp_dir().join(format!("noid-decoy3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut mgr = SecurityManager::new(dir.clone());
        mgr.derive_key("true-pin-123").unwrap();
        let true_key = mgr.get_master_key().unwrap();
        mgr.save_decoy_pin_hash("decoy-pin-456").unwrap();
        mgr.derive_decoy_key("decoy-pin-456").unwrap();
        let decoy_key = mgr.get_master_key().unwrap();
        assert_ne!(true_key, decoy_key);
        // Same PIN under different salts must also differ.
        mgr.derive_key("shared-pin-99").unwrap();
        let a = mgr.get_master_key().unwrap();
        mgr.derive_decoy_key("shared-pin-99").unwrap();
        assert_ne!(a, mgr.get_master_key().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
