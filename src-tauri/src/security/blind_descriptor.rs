//! META-03: encrypted DHT peer descriptors.
//!
//! A descriptor is a fixed 1024-byte AES-256-GCM blob whose key derives
//! from the owner's Ed25519 identity pubkey and the day epoch:
//! `K = HKDF(ed_pub, "noid:dhtdesc:v1" || day)`. Only someone who already
//! knows the PeerId can derive K — DHT storage nodes and passive crawlers
//! see an opaque blob under a blinded record key
//! (`HKDF(ed_pub, "noid:desckey:v1" || day)`) that reveals no owner and
//! rotates daily, so records cannot be enumerated or correlated across
//! days.
//!
//! Layout: `nonce(12) || ciphertext(≤ 1012)`. The plaintext is
//! `DESC || u16be len || json || zeros`; inner signed records keep their
//! Ed25519 signatures — readers verify AFTER unwrapping.
//!
//! Mixed-version: publishers dual-publish (legacy signed JSON + blinded
//! descriptor); readers try blinded first and fall back to legacy.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use libp2p::kad;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

pub const DESCRIPTOR_BYTES: usize = 1024;
const MAGIC: &[u8; 4] = b"DESC";
/// Max plaintext payload: 1024 = nonce(12) + tag(16) + magic(4) + len(2) + inner.
const MAX_INNER: usize = DESCRIPTOR_BYTES - 12 - 16 - 4 - 2;

fn descriptor_key(ed_pub: &[u8], day: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"noid:dhtdesc:v1"), ed_pub);
    let mut k = [0u8; 32];
    let _ = hk.expand(&day.to_be_bytes(), &mut k);
    k
}

/// The blinded Kademlia record key — no peer id on the wire or in store.
pub fn blind_record_key(ed_pub: &[u8], day: u64) -> kad::RecordKey {
    let hk = Hkdf::<Sha256>::new(Some(b"noid:desckey:v1"), ed_pub);
    let mut k = [0u8; 32];
    let _ = hk.expand(&day.to_be_bytes(), &mut k);
    kad::RecordKey::new(&k)
}

/// Wrap an arbitrary JSON payload into a fixed 1024-byte descriptor.
/// Returns `None` when the payload exceeds the descriptor capacity.
pub fn wrap_descriptor(ed_pub: &[u8], day: u64, plaintext: &[u8]) -> Option<Vec<u8>> {
    if plaintext.len() > MAX_INNER {
        return None;
    }
    let mut key = descriptor_key(ed_pub, day);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let mut frame = Vec::with_capacity(MAX_INNER);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    frame.extend_from_slice(plaintext);
    frame.resize(MAX_INNER + MAGIC.len() + 2, 0);
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(&Nonce::from(nonce), frame.as_ref()).ok()?;
    key.zeroize();
    let mut out = Vec::with_capacity(DESCRIPTOR_BYTES);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    (out.len() == DESCRIPTOR_BYTES).then_some(out)
}

/// Unwrap a descriptor — `None` on wrong key, tamper, or bad frame.
pub fn unwrap_descriptor(ed_pub: &[u8], day: u64, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() != DESCRIPTOR_BYTES {
        return None;
    }
    let mut key = descriptor_key(ed_pub, day);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce = Nonce::from(<[u8; 12]>::try_from(&blob[..12]).ok()?);
    let frame = cipher.decrypt(&nonce, &blob[12..]).ok();
    key.zeroize();
    let frame = frame?;
    if &frame[..4] != MAGIC {
        return None;
    }
    let len = u16::from_be_bytes(frame[4..6].try_into().ok()?) as usize;
    (len <= MAX_INNER).then(|| frame[6..6 + len].to_vec())
}

/// The days a fresh descriptor can live under — today and yesterday at
/// the rotation boundary.
pub fn active_days() -> [u64; 2] {
    let day = crate::p2p::blind_box::current_day();
    [day, day.saturating_sub(1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_roundtrip() {
        let pub_bytes = [7u8; 32];
        let blob = wrap_descriptor(&pub_bytes, 42, b"{\"k\":\"v\"}").unwrap();
        assert_eq!(blob.len(), DESCRIPTOR_BYTES);
        assert_eq!(unwrap_descriptor(&pub_bytes, 42, &blob).unwrap(), b"{\"k\":\"v\"}");
        assert!(unwrap_descriptor(&pub_bytes, 43, &blob).is_none());
        assert!(unwrap_descriptor(&[9u8; 32], 42, &blob).is_none());
    }
}
