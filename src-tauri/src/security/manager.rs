//! Security Manager
//!
//! Управление мастер-ключом, шифрование для локального хранения

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use base64::Engine;
use zeroize::Zeroize;

pub struct SecurityManager {
    master_key: Option<[u8; 32]>,
    data_dir: PathBuf,
}

impl SecurityManager {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            master_key: None,
            data_dir,
        }
    }

    /// Derives a master key from a PIN using Argon2id.
    pub fn derive_key(&mut self, pin: &str) -> Result<()> {
        let salt_path = self.data_dir.join("salt.bin");
        let salt = if salt_path.exists() {
            let salt_bytes = std::fs::read(&salt_path)?;
            if salt_bytes.len() < 16 {
                return Err(anyhow!("Salt file too short, possible corruption"));
            }
            SaltString::from_b64(&base64::engine::general_purpose::STANDARD_NO_PAD.encode(&salt_bytes))?
        } else {
            // Phase 3.7: If noid.db exists but salt.bin is missing, refuse to generate new salt
            let db_path = self.data_dir.join("noid.db");
            if db_path.exists() {
                return Err(anyhow!(
                    "salt.bin is missing but noid.db exists — \
                     refusing to generate a new salt (would produce a different master key \
                     and make existing messages undecryptable). \
                     Restore salt.bin from backup or wipe noid.db to start fresh."
                ));
            }
            let mut salt_bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt_bytes);
            std::fs::write(&salt_path, salt_bytes)?;
            SaltString::from_b64(&base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt_bytes))?
        };
        // Phase 3.2: Use explicit Argon2id parameters (64MB, 3 iterations, 1 lane)
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 1, None)
                .map_err(|e| anyhow!("Argon2 params error: {}", e))?,
        );
        let hash = argon2
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|e| anyhow!("KDF error: {}", e))?;

        let mut key = [0u8; 32];
        let hash_output = hash.hash.ok_or_else(|| anyhow!("No hash output"))?;
        key.copy_from_slice(&hash_output.as_ref()[..32]);

        self.master_key = Some(key);
        Ok(())
    }

    /// Whether first-run PIN setup has already completed — `setup_pins`
    /// must refuse to overwrite an existing security state (S4): a second
    /// call would rotate the master key and orphan every encrypted record.
    pub fn is_setup_complete(&self) -> bool {
        self.data_dir.join("true_pin.hash").exists()
    }

    /// Phase 3.1: Save a verified hash of the true PIN (PHC format) for login verification.
    pub fn save_true_pin_hash(&self, pin: &str) -> Result<()> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 1, None)
                .map_err(|e| anyhow!("Argon2 params error: {}", e))?,
        );
        let hash = argon2
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|e| anyhow!("KDF error: {}", e))?
            .to_string();
        fs::write(self.data_dir.join("true_pin.hash"), hash)?;
        Ok(())
    }

    /// Phase 3.1: Verify a PIN against the stored true_pin.hash.
    /// Returns Ok(true) if PIN is correct, Ok(false) if incorrect, Err if hash file missing/corrupt.
    pub fn verify_true_pin(&self, pin: &str) -> Result<bool> {
        let hash_path = self.data_dir.join("true_pin.hash");
        if !hash_path.exists() {
            return Err(anyhow!("true_pin.hash not found — please run setup_pins again"));
        }
        let hash_str = fs::read_to_string(hash_path)?;
        let parsed_hash = PasswordHash::new(&hash_str)
            .map_err(|e| anyhow!("Invalid true_pin.hash format: {}", e))?;
        Ok(Argon2::default()
            .verify_password(pin.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn get_master_key(&self) -> Result<[u8; 32]> {
        self.master_key
            .ok_or_else(|| anyhow!("Security manager not initialized with PIN"))
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = Some(key);
    }

    /// S14: message-content ciphertexts carry a `NOIDMSG2` magic and are
    /// sealed under the "msg" domain subkey — a blob relocated from another
    /// domain (key envelope, field, audit) cannot be decrypted through the
    /// message read path. Legacy `nonce||ct` blobs written under the raw
    /// master key are still readable.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let master = self.get_master_key()?;
        let key = crate::security::derive_domain_key(&master, "msg");
        let cipher = Aes256Gcm::new_from_slice(&key)?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption error: {}", e))?;

        const MSG_MAGIC: &[u8; 8] = b"NOIDMSG2";
        let mut result = Vec::with_capacity(MSG_MAGIC.len() + 12 + ciphertext.len());
        result.extend_from_slice(MSG_MAGIC);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let master = self.get_master_key()?;
        const MSG_MAGIC: &[u8; 8] = b"NOIDMSG2";

        let (key, body): ([u8; 32], &[u8]) = if data.starts_with(MSG_MAGIC) {
            (
                crate::security::derive_domain_key(&master, "msg"),
                &data[MSG_MAGIC.len()..],
            )
        } else {
            // Legacy format: raw nonce||ct sealed under the master key.
            (master, data)
        };

        if body.len() < 12 {
            return Err(anyhow!("Invalid encrypted data"));
        }

        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let (nonce_bytes, ciphertext) = body.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption error: {}", e))
    }

    pub fn set_kill_pin(&self, pin: &str) -> Result<()> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        // Same hardened Argon2id parameters as the true PIN — the kill hash
        // must resist the same offline brute-force as the login hash.
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 1, None)
                .map_err(|e| anyhow!("Argon2 params error: {}", e))?,
        );
        let hash = argon2
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|e| anyhow!("KDF error: {}", e))?
            .to_string();

        fs::write(self.data_dir.join("kill.hash"), hash)?;
        Ok(())
    }

    pub fn verify_kill_pin(&self, pin: &str) -> bool {
        let hash_path = self.data_dir.join("kill.hash");
        if !hash_path.exists() {
            return false;
        }

        if let Ok(hash_str) = fs::read_to_string(hash_path) {
            match PasswordHash::new(&hash_str) {
                Ok(parsed_hash) => {
                    return Argon2::default()
                        .verify_password(pin.as_bytes(), &parsed_hash)
                        .is_ok();
                }
                // S18: a corrupt kill.hash silently disabled the wipe —
                // surface it loudly so the user re-sets the pin.
                Err(e) => log::error!("kill.hash is corrupt ({}) — wipe is DISABLED, re-set the kill PIN", e),
            }
        } else {
            log::error!("kill.hash unreadable — wipe is DISABLED, re-set the kill PIN");
        }
        false
    }

    pub fn kill_everything(&mut self) -> Result<()> {
        let result = if self.data_dir.exists() {
            crate::security::secure_delete::secure_delete_dir(&self.data_dir)
        } else {
            Ok(())
        };
        // S18: the in-memory master key must not survive a wipe — take +
        // zeroize regardless of whether the shred fully succeeded.
        if let Some(mut k) = self.master_key.take() {
            k.zeroize();
        }
        result
    }
}

impl Drop for SecurityManager {
    fn drop(&mut self) {
        if let Some(mut key) = self.master_key {
            key.zeroize();
        }
    }
}
