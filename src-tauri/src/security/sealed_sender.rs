//! META-02: Sealed Sender envelopes for blind mailbox delivery.
//!
//! A mailbox that only sees `StoreBlind` learns nothing about the sender:
//! no `sender_peer_id`, no `RatchetHeader`, no signature. The whole
//! envelope is one ECIES blob of exactly 4096 bytes addressed to the
//! recipient's X3DH identity key:
//!
//! ```text
//! [ ephemeral X25519 pub (32) | nonce (12) | AES-256-GCM ct (4052) ]
//! ```
//!
//! Inside the AEAD the framed plaintext is
//! `SLD1 || u16be sender_len || sender || u16be ref_len || ref ||
//!   u32be payload_len || payload || zeros`
//! padded to a fixed width, so every sealed envelope is wire-identical in
//! size. `ref` is the sender's stable message id — it lets the recipient
//! echo an end-to-end delivery receipt without the mailbox learning it.
//! Recipients open with their static X3DH identity secret.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::Rng;
use zeroize::Zeroize;

pub const SEALED_ENVELOPE_BYTES: usize = 4096;
const INNER_BYTES: usize = 4052 - 16; // ct size minus the GCM tag
const MAGIC: &[u8; 4] = b"SLD1";
const MAX_SENDER_LEN: usize = 128;
const MAX_REF_LEN: usize = 64;
const MAX_PAYLOAD_LEN: usize =
    INNER_BYTES - 4 - 2 - MAX_SENDER_LEN - 2 - MAX_REF_LEN - 4;
const HKDF_INFO: &[u8] = b"noid:sealed-sender:v1";

fn frame(sender_peer_id: &str, ref_id: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let sid = sender_peer_id.as_bytes();
    let rid = ref_id.as_bytes();
    if sid.len() > MAX_SENDER_LEN || rid.len() > MAX_REF_LEN || payload.len() > MAX_PAYLOAD_LEN {
        return None;
    }
    let mut buf = Vec::with_capacity(INNER_BYTES);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(sid.len() as u16).to_be_bytes());
    buf.extend_from_slice(sid);
    buf.resize(4 + 2 + MAX_SENDER_LEN, 0);
    buf.extend_from_slice(&(rid.len() as u16).to_be_bytes());
    buf.extend_from_slice(rid);
    buf.resize(4 + 2 + MAX_SENDER_LEN + 2 + MAX_REF_LEN, 0);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf.resize(INNER_BYTES, 0);
    Some(buf)
}

fn unframe(buf: &[u8]) -> Option<(String, String, Vec<u8>)> {
    if buf.len() != INNER_BYTES || &buf[..4] != MAGIC {
        return None;
    }
    let slen = u16::from_be_bytes(buf[4..6].try_into().ok()?) as usize;
    if slen > MAX_SENDER_LEN {
        return None;
    }
    let sender = std::str::from_utf8(&buf[6..6 + slen]).ok()?.to_string();
    let off = 4 + 2 + MAX_SENDER_LEN;
    let rlen = u16::from_be_bytes(buf[off..off + 2].try_into().ok()?) as usize;
    if rlen > MAX_REF_LEN {
        return None;
    }
    let ref_id = std::str::from_utf8(&buf[off + 2..off + 2 + rlen])
        .ok()?
        .to_string();
    let off2 = off + 2 + MAX_REF_LEN;
    let plen = u32::from_be_bytes(buf[off2..off2 + 4].try_into().ok()?) as usize;
    if plen > MAX_PAYLOAD_LEN || off2 + 4 + plen > buf.len() {
        return None;
    }
    Some((sender, ref_id, buf[off2 + 4..off2 + 4 + plen].to_vec()))
}

fn derive_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    let _ = hk.expand(HKDF_INFO, &mut key);
    key
}

/// Seal `payload` + sender id + `ref_id` (stable msg id for the e2e
/// delivery receipt) into a fixed 4096-byte envelope for
/// `recipient_identity_pub` (the recipient's X3DH identity public key).
pub fn seal(
    recipient_identity_pub: &[u8],
    sender_peer_id: &str,
    ref_id: &str,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let pub_bytes: [u8; 32] = recipient_identity_pub.try_into().ok()?;
    let recipient_pub = PublicKey::from(pub_bytes);
    let eph = StaticSecret::random_from_rng(&mut rand::rng());
    let shared = eph.diffie_hellman(&recipient_pub);
    let mut key_bytes = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let inner = frame(sender_peer_id, ref_id, payload)?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce_bytes), inner.as_ref())
        .ok()?;
    key_bytes.zeroize();
    let mut out = Vec::with_capacity(SEALED_ENVELOPE_BYTES);
    out.extend_from_slice(&PublicKey::from(&eph).to_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    if out.len() != SEALED_ENVELOPE_BYTES {
        return None;
    }
    Some(out)
}

/// Open a sealed envelope with our X3DH identity secret.
/// Returns `(sender_peer_id, ref_id, payload)`; `None` on wrong key/tamper.
pub fn open(
    identity_secret_bytes: &[u8],
    blob: &[u8],
) -> Option<(String, String, Vec<u8>)> {
    if blob.len() != SEALED_ENVELOPE_BYTES {
        return None;
    }
    let sec_bytes: [u8; 32] = identity_secret_bytes.try_into().ok()?;
    let secret = StaticSecret::from(sec_bytes);
    let eph_pub = PublicKey::from(<[u8; 32]>::try_from(&blob[..32]).ok()?);
    let shared = secret.diffie_hellman(&eph_pub);
    let mut key_bytes = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::from(<[u8; 12]>::try_from(&blob[32..44]).ok()?);
    let inner = cipher.decrypt(&nonce, &blob[44..]).ok();
    key_bytes.zeroize();
    unframe(&inner?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let sec = StaticSecret::random_from_rng(&mut rand::rng());
        let pubk = PublicKey::from(&sec);
        let blob = seal(&pubk.to_bytes(), "sender-peer", "msg-42", b"hello mailbox").unwrap();
        assert_eq!(blob.len(), SEALED_ENVELOPE_BYTES);
        let (sender, ref_id, payload) = open(&sec.to_bytes(), &blob).unwrap();
        assert_eq!(sender, "sender-peer");
        assert_eq!(ref_id, "msg-42");
        assert_eq!(payload, b"hello mailbox");
    }

    #[test]
    fn wrong_key_fails() {
        let sec1 = StaticSecret::random_from_rng(&mut rand::rng());
        let sec2 = StaticSecret::random_from_rng(&mut rand::rng());
        let pub1 = PublicKey::from(&sec1);
        let blob = seal(&pub1.to_bytes(), "s", "r", b"x").unwrap();
        assert!(open(&sec2.to_bytes(), &blob).is_none());
    }
}
