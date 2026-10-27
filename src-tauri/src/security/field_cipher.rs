//! FieldCipher — encrypts sensitive SQLite columns with the login-derived
//! master key and produces deterministic HMAC lookup tokens.
//!
//! Layout: `encrypt_bytes` → `nonce(12) || AES-256-GCM(key, plaintext)`.
//! `hmac_hex` → deterministic hex token so `WHERE peer_hmac = ?` still works
//! without storing the plaintext peer id.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// S14: field ciphertexts written since the domain split carry this magic —
/// they are sealed under the "db-field" subkey, so a blob relocated from
/// another domain (messages, key envelopes, audit) cannot be decrypted via
/// the field path, and vice versa.
const FIELD_MAGIC: &[u8; 6] = b"NOIDF2";
/// Text columns get a printable marker instead: `f2:` + base64.
const TEXT_MAGIC: &str = "f2:";

pub struct FieldCipher {
    /// Master key — still used for HMAC lookup tokens and for reading
    /// ciphertexts written before the domain split (no magic).
    key: [u8; 32],
    /// "db-field" domain subkey for all new encryptions.
    enc_key: [u8; 32],
}

impl FieldCipher {
    /// `key` is the login-derived master key; the encryption key is the
    /// derived "db-field" subkey (S14).
    pub fn new(key: [u8; 32]) -> Self {
        let enc_key = crate::security::derive_domain_key(&key, "db-field");
        Self { key, enc_key }
    }

    fn cipher(&self) -> Aes256Gcm {
        // unwrap safety: Aes256Gcm accepts any 32-byte key
        Aes256Gcm::new_from_slice(&self.enc_key).expect("32-byte AES key")
    }

    fn legacy_cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES key")
    }

    /// FIELD_MAGIC || nonce(12) || ciphertext||tag
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("field encrypt: {}", e))?;
        let mut out = Vec::with_capacity(FIELD_MAGIC.len() + 12 + ct.len());
        out.extend_from_slice(FIELD_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (cipher, body): (Aes256Gcm, &[u8]) = if data.starts_with(FIELD_MAGIC) {
            (self.cipher(), &data[FIELD_MAGIC.len()..])
        } else {
            (self.legacy_cipher(), data)
        };
        if body.len() < 13 {
            return Err(anyhow!("field decrypt: ciphertext too short"));
        }
        let (nonce_bytes, ct) = body.split_at(12);
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| anyhow!("field decrypt: {}", e))
    }

    /// Base64 text form for TEXT columns — `f2:` prefix marks domain-keyed
    /// ciphertext; unprefixed values are legacy master-key ciphertexts.
    pub fn encrypt_text(&self, plaintext: &str) -> Result<String> {
        Ok(format!(
            "{}{}",
            TEXT_MAGIC,
            base64::engine::general_purpose::STANDARD
                .encode(self.encrypt_bytes(plaintext.as_bytes())?)
        ))
    }

    pub fn decrypt_text(&self, stored: &str) -> Result<String> {
        let body = stored.strip_prefix(TEXT_MAGIC).unwrap_or(stored);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| anyhow!("field decode: {}", e))?;
        let plain = self.decrypt_bytes(&raw)?;
        String::from_utf8(plain).map_err(|e| anyhow!("field utf8: {}", e))
    }

    /// Deterministic lookup token — equality searches without plaintext.
    /// Distinct namespace per column so tokens aren't cross-correlatable.
    pub fn hmac_hex(&self, namespace: &str, value: &str) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"noid-field-hmac-v1");
        mac.update(namespace.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl Drop for FieldCipher {
    fn drop(&mut self) {
        self.key.zeroize();
        self.enc_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes_and_text() {
        let c = FieldCipher::new([7u8; 32]);
        let enc = c.encrypt_bytes(b"secret").unwrap();
        assert_eq!(c.decrypt_bytes(&enc).unwrap(), b"secret");
        let t = c.encrypt_text("peer-id-123").unwrap();
        assert_eq!(c.decrypt_text(&t).unwrap(), "peer-id-123");
    }

    #[test]
    fn hmac_deterministic_and_namespaced() {
        let c = FieldCipher::new([1u8; 32]);
        assert_eq!(c.hmac_hex("peer", "abc"), c.hmac_hex("peer", "abc"));
        assert_ne!(c.hmac_hex("peer", "abc"), c.hmac_hex("sender", "abc"));
        assert_ne!(c.hmac_hex("peer", "abc"), c.hmac_hex("peer", "abd"));
    }

    #[test]
    fn wrong_key_fails() {
        let a = FieldCipher::new([1u8; 32]);
        let b = FieldCipher::new([2u8; 32]);
        let enc = a.encrypt_text("x").unwrap();
        assert!(b.decrypt_text(&enc).is_err());
    }
}
