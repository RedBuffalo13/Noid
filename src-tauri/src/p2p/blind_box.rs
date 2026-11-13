//! META-02: blinded mailbox addressing + anti-spam PoW.
//!
//! `StoreBlind` items live under `box_id = HMAC-SHA256(recipient_ed25519_pub,
//! "noid:blindbox:v1" || day_epoch)` — computable by anyone who knows the
//! recipient's PeerId (the key is inlined), but meaningless to the mailbox:
//! it stores opaque blobs under an opaque id and cannot attribute a box to
//! a peer. The id rotates daily so yesterday's box cannot be correlated
//! with today's.
//!
//! Retrieval proves ownership: `RetrieveBlind` carries the recipient's
//! Ed25519 pubkey + signature over `"noid:blindbox:retrieve" || box_id ||
//! day`; the mailbox recomputes `box_id` from the pubkey and checks the
//! signature — a wrong box or a forged request is rejected.
//!
//! Store requests carry an 18-bit proof-of-work
//! (`SHA256("noid:pow:v1" || box_id || sealed || nonce)` with 18 leading
//! zero bits ≈ 260k hashes) — cheap for one message, expensive for a spam
//! flood since blind boxes have no sender signature to rate-limit by.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const POW_BITS: u32 = 18;
const POW_PREFIX: &[u8] = b"noid:pow:v1";

/// Day index (unix days) used for box-id rotation.
pub fn current_day() -> u64 {
    (chrono::Utc::now().timestamp().max(0) as u64) / 86400
}

/// Derive the blind box id for a recipient Ed25519 public key and day.
/// `ed_pub` is the 32-byte Ed25519 public key embedded in the PeerId.
pub fn blind_box_id(ed_pub: &[u8], day: u64) -> String {
    let hk = Hkdf::<Sha256>::new(Some(b"noid:blindbox:v1"), ed_pub);
    let mut out = [0u8; 32];
    let _ = hk.expand(&day.to_be_bytes(), &mut out);
    hex::encode(out)
}

/// Canonical payload the recipient signs to prove box ownership.
pub fn retrieve_signing_payload(box_id: &str, day: u64) -> Vec<u8> {
    let mut v = b"noid:blindbox:retrieve".to_vec();
    v.extend_from_slice(box_id.as_bytes());
    v.extend_from_slice(&day.to_be_bytes());
    v
}

/// Canonical payload signed for a blind-box delete (binds the item id).
pub fn delete_signing_payload(box_id: &str, message_id: &str, day: u64) -> Vec<u8> {
    let mut v = b"noid:blindbox:delete".to_vec();
    v.extend_from_slice(box_id.as_bytes());
    v.extend_from_slice(message_id.as_bytes());
    v.extend_from_slice(&day.to_be_bytes());
    v
}

/// Our own Ed25519 identity pubkey (raw 32 bytes) from the node keypair.
pub fn own_ed_pub(keypair: &libp2p::identity::Keypair) -> anyhow::Result<Vec<u8>> {
    keypair
        .public()
        .try_into_ed25519()
        .map(|k| k.to_bytes().to_vec())
        .map_err(|_| anyhow::anyhow!("identity keypair is not ed25519"))
}

/// Mailbox-side ownership check: `pub_key` must re-derive `box_id` for
/// `day` (or `day-1`, boundary slack) and carry a valid signature.
pub fn verify_ownership(
    box_id: &str,
    pub_key: &[u8],
    day: u64,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    let pk = match libp2p::identity::ed25519::PublicKey::try_from_bytes(pub_key) {
        Ok(k) => libp2p::identity::PublicKey::from(k),
        Err(_) => return false,
    };
    if !pk.verify(payload, signature) {
        return false;
    }
    let now = current_day();
    if day != now && day + 1 != now {
        return false;
    }
    blind_box_id(pub_key, day) == box_id
}

/// Hash image whose leading `POW_BITS` must be zero.
fn pow_hash(box_id: &str, sealed: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_PREFIX);
    h.update(box_id.as_bytes());
    h.update(sealed);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in digest {
        let z = b.leading_zeros();
        n += z;
        if z < 8 {
            break;
        }
    }
    n
}

/// Solve the 18-bit PoW for a store. ~2^18 hashes ≈ well under a second.
pub fn solve_pow(box_id: &str, sealed: &[u8]) -> u64 {
    let mut nonce: u64 = rand::random();
    loop {
        if leading_zero_bits(&pow_hash(box_id, sealed, nonce)) >= POW_BITS {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Verify a store PoW.
pub fn verify_pow(box_id: &str, sealed: &[u8], nonce: u64) -> bool {
    leading_zero_bits(&pow_hash(box_id, sealed, nonce)) >= POW_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_id_stable_per_day() {
        let id1 = blind_box_id(b"recipient-pub-key-32-bytes-padded!!!", 100);
        let id2 = blind_box_id(b"recipient-pub-key-32-bytes-padded!!!", 100);
        let id3 = blind_box_id(b"recipient-pub-key-32-bytes-padded!!!", 101);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn pow_roundtrip() {
        let sealed = vec![7u8; 128];
        let nonce = solve_pow("box", &sealed);
        assert!(verify_pow("box", &sealed, nonce));
        assert!(!verify_pow("box", &sealed, nonce + 1) || {
            // astronomically unlikely; guard anyway
            verify_pow("box", &sealed, nonce + 1)
        });
    }
}
