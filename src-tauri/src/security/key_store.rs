//! Encrypted-at-rest key material.
//!
//! Format: `NOIDKEY1 || nonce(12) || AES-256-GCM(master_key, material) || tag`.
//! All node key files (identity.key, dht.key) are stored only in this
//! envelope — never as raw protobuf/key bytes. Decryption is possible only
//! after a successful login derived the master key from the PIN.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"NOIDKEY1";
/// S14: v2 envelopes are sealed under the "keystore" domain subkey — a
/// v2 blob relocated into a message/field/audit slot cannot be decrypted
/// through that domain's read path.
const MAGIC_V2: &[u8; 8] = b"NOIDKEY2";
const NONCE_LEN: usize = 12;

/// Whether the file at `path` is already in the encrypted envelope format.
pub fn is_encrypted(path: &Path) -> bool {
    std::fs::read(path)
        .map(|d| d.starts_with(MAGIC_V2) || d.starts_with(MAGIC))
        .unwrap_or(false)
}

/// Encrypt `material` under `master_key` and write the envelope atomically
/// (tmp file + rename) so a crash cannot leave a half-written key file.
pub fn save(path: &Path, material: &[u8], master_key: &[u8; 32]) -> Result<()> {
    let key = crate::security::derive_domain_key(master_key, "keystore");
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Invalid master key: {}", e))?;

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), material)
        .map_err(|e| anyhow!("Key encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(MAGIC_V2.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Decrypt an envelope file. Fails on wrong PIN (GCM tag mismatch),
/// corrupted/truncated data, or a non-envelope (legacy plaintext) file.
pub fn load(path: &Path, master_key: &[u8; 32]) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow!("Cannot read key file {}: {}", path.display(), e))?;
    decrypt_bytes(&data, master_key)
}

fn decrypt_bytes(data: &[u8], master_key: &[u8; 32]) -> Result<Vec<u8>> {
    let (key, body): ([u8; 32], &[u8]) = if data.starts_with(MAGIC_V2) {
        (
            crate::security::derive_domain_key(master_key, "keystore"),
            &data[MAGIC_V2.len()..],
        )
    } else if data.starts_with(MAGIC) {
        (*master_key, &data[MAGIC.len()..])
    } else {
        return Err(anyhow!("Key file is not in NOIDKEY envelope format"));
    };
    if body.len() < NONCE_LEN {
        return Err(anyhow!("Key envelope truncated"));
    }
    let (nonce, ciphertext) = body.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Invalid master key: {}", e))?;
    let mut plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("Key decryption failed — wrong PIN or corrupted key file"))?;
    let out = plaintext.clone();
    plaintext.zeroize();
    Ok(out)
}

/// Load a key file, transparently migrating a legacy plaintext file:
/// read the raw bytes, re-write them as an envelope, return the material.
/// Used once on the first login after the security upgrade.
pub fn load_or_migrate(path: &Path, master_key: &[u8; 32]) -> Result<Vec<u8>> {
    if is_encrypted(path) {
        let material = load(path, master_key)?;
        // S14: upgrade legacy NOIDKEY1 envelopes to the domain-keyed
        // NOIDKEY2 format so v1 blobs stop existing on disk — closing the
        // cross-domain relocation oracle for private key material.
        let is_v1 = std::fs::read(path)
            .map(|d| d.starts_with(MAGIC) && !d.starts_with(MAGIC_V2))
            .unwrap_or(false);
        if is_v1 {
            if let Err(e) = save(path, &material, master_key) {
                log::warn!("Key envelope upgrade to NOIDKEY2 failed for {}: {}", path.display(), e);
            } else {
                log::info!("Upgraded {} to NOIDKEY2 domain-keyed envelope", path.display());
            }
        }
        return Ok(material);
    }
    let raw = std::fs::read(path)
        .map_err(|e| anyhow!("Cannot read legacy key file {}: {}", path.display(), e))?;
    save(path, &raw, master_key)?;
    log::info!("Migrated {} to encrypted key envelope", path.display());
    Ok(raw)
}

/// Load (or migrate) a key file; when the file does not exist, call
/// `material_fn` to generate fresh material and persist it encrypted.
pub fn load_or_create<F>(path: &Path, master_key: &[u8; 32], material_fn: F) -> Result<Vec<u8>>
where
    F: FnOnce() -> Result<Vec<u8>>,
{
    if path.exists() {
        load_or_migrate(path, master_key)
    } else {
        let material = material_fn()?;
        save(path, &material, master_key)?;
        Ok(material)
    }
}

/// Load (or migrate) a key file; on ANY read/decrypt/validation failure the
/// file is quarantined and `material_fn` generates fresh material — a corrupt
/// key must not wedge the node. `validate` sanity-checks legacy plaintext
/// material before it is wrapped into an envelope; callers decide what
/// "valid" means for their key kind. Returns `true` in `generated` when the
/// material was freshly generated (the peer identity may have changed).
pub fn load_or_regen<F, V>(
    path: &Path,
    master_key: &[u8; 32],
    material_fn: F,
    validate: V,
    generated: &mut bool,
) -> Result<Vec<u8>>
where
    F: FnOnce() -> Result<Vec<u8>>,
    V: Fn(&[u8]) -> bool,
{
    if path.exists() && !is_encrypted(path) {
        // Plaintext (pre-envelope) file: validate before migrating so
        // garbage is quarantined instead of wrapped into an envelope.
        let ok = std::fs::read(path).map(|raw| validate(&raw)).unwrap_or(false);
        if !ok {
            log::warn!("Key file {} has invalid plaintext — quarantining", path.display());
            crate::util::quarantine::quarantine(path)
                .map_err(|e| anyhow!("quarantine failed: {}", e))?;
        }
    }
    let existed = path.exists();
    match load_or_migrate(path, master_key) {
        Ok(b) => Ok(b),
        Err(e) => {
            if existed {
                log::warn!(
                    "Key file {} unreadable ({}) — quarantining and regenerating",
                    path.display(),
                    e
                );
            }
            crate::util::quarantine::quarantine(path)
                .map_err(|qe| anyhow!("quarantine failed: {}", qe))?;
            let fresh = material_fn()?;
            save(path, &fresh, master_key)?;
            *generated = existed;
            Ok(fresh)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        let key = [7u8; 32];
        let material = b"secret key material".to_vec();
        save(&path, &material, &key).unwrap();
        assert!(is_encrypted(&path));
        // Envelope must not contain the raw material.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(material.len()).any(|w| w == material.as_slice()));
        assert!(raw.starts_with(MAGIC_V2));
        assert_eq!(load(&path, &key).unwrap(), material);
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        save(&path, b"data", &[1u8; 32]).unwrap();
        assert!(load(&path, &[2u8; 32]).is_err());
    }

    #[test]
    fn legacy_plaintext_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        let material = b"legacy raw key".to_vec();
        std::fs::write(&path, &material).unwrap();
        let key = [9u8; 32];
        let loaded = load_or_migrate(&path, &key).unwrap();
        assert_eq!(loaded, material);
        assert!(is_encrypted(&path));
        assert_eq!(load(&path, &key).unwrap(), material);
    }

    #[test]
    fn create_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        let key = [3u8; 32];
        let m = load_or_create(&path, &key, || Ok(b"fresh".to_vec())).unwrap();
        assert_eq!(m, b"fresh".to_vec());
        assert!(is_encrypted(&path));
    }
}
