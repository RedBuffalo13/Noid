//! Encrypted room messaging.
//!
//! A room is defined by a 32-byte `RoomKey` (AES-256-GCM). The room id is a
//! fingerprint of the key — knowing the id does NOT grant decryption, but
//! only key holders can produce it, which keeps topic names unlinkable to
//! room metadata.
//!
//! Wire format (`RoomEnvelope`, gossipsub payload):
//!   `{ msg_id, sender_peer_id, ts, ciphertext, signature }`
//! where ciphertext = AES-256-GCM(room_key, plaintext) and signature is the
//! sender's Ed25519 libp2p identity signature over
//! `"noid-room-v1" || room_id || msg_id || ts || ciphertext`.
//! Receivers verify the signature against the public key embedded in
//! `sender_peer_id` — forged or tampered envelopes are dropped.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Symmetric room key. `room_id` is a fingerprint — safe to share as a topic.
pub struct RoomKey(pub [u8; 32]);

impl RoomKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        Self(k)
    }

    /// Room identifier = hex(SHA-256(key))[:32] — derived, never transmitted
    /// with the key itself.
    pub fn room_id(&self) -> String {
        let h = Sha256::digest(self.0);
        hex::encode(&h[..16])
    }
}

impl Drop for RoomKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypted + signed room message — the only thing gossipsub ever carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEnvelope {
    pub msg_id: String,
    pub sender_peer_id: String,
    pub ts: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Canonical signing bytes for a room envelope.
pub fn envelope_payload(room_id: &str, msg_id: &str, ts: &str, ciphertext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + ciphertext.len());
    v.extend_from_slice(b"noid-room-v1");
    v.extend_from_slice(room_id.as_bytes());
    v.extend_from_slice(msg_id.as_bytes());
    v.extend_from_slice(ts.as_bytes());
    v.extend_from_slice(ciphertext);
    v
}

/// Encrypt `plaintext` and sign with the sender's libp2p identity key.
pub fn seal(
    key: &[u8; 32],
    room_id: &str,
    keypair: &libp2p::identity::Keypair,
    msg_id: &str,
    plaintext: &[u8],
) -> Result<RoomEnvelope> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("room key: {}", e))?;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|e| anyhow!("room encrypt: {}", e))?;
    // nonce || ct || tag
    let mut ciphertext = Vec::with_capacity(12 + ct.len());
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&ct);

    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let sender_peer_id = libp2p::PeerId::from(keypair.public()).to_string();
    let signature = crate::security::identity_sig::sign_payload(
        keypair,
        &envelope_payload(room_id, msg_id, &ts, &ciphertext),
    )?;
    Ok(RoomEnvelope {
        msg_id: msg_id.to_string(),
        sender_peer_id,
        ts,
        ciphertext,
        signature,
    })
}

/// Verify the sender signature and decrypt. Fails closed: any tamper,
/// wrong sender or missing key → Err.
pub fn open(key: &[u8; 32], room_id: &str, env: &RoomEnvelope) -> Result<Vec<u8>> {
    let ok = crate::security::identity_sig::verify_payload(
        &env.sender_peer_id,
        &envelope_payload(room_id, &env.msg_id, &env.ts, &env.ciphertext),
        &env.signature,
    );
    if !ok {
        return Err(anyhow!("room envelope signature invalid"));
    }
    // S23: freshness — a signed replay from long ago (or a far-future ts)
    // is rejected even though the signature verifies.
    let fresh = chrono::DateTime::parse_from_rfc3339(&env.ts)
        .map(|ts| {
            let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
            age <= chrono::Duration::days(30) && age >= chrono::Duration::days(-1)
        })
        .unwrap_or(false);
    if !fresh {
        return Err(anyhow!("room envelope stale timestamp"));
    }
    if env.ciphertext.len() < 13 {
        return Err(anyhow!("room envelope too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("room key: {}", e))?;
    let (nonce, ct) = env.ciphertext.split_at(12);
    cipher
        .decrypt(&Nonce::from(<[u8; 12]>::try_from(nonce)?), ct)
        .map_err(|_| anyhow!("room envelope decrypt failed"))
}

// ---------------------------------------------------------------------------
// META-04: SealedRoomEnvelopeV2 + rotating topics.
//
// V1 envelopes expose `sender_peer_id` and `ts` in the clear to every
// transit gossipsub peer. V2 puts the WHOLE envelope (sender, ts, inner
// ciphertext, signature) inside a second AES-256-GCM layer keyed by
// `HKDF(room_key, "noid-room-v2-seal")` — wire bytes are
// `NRV2 || nonce || outer_ct`, indistinguishable from noise. Members
// unwrap the outer layer and run the exact V1 checks inside, so
// membership auth is unchanged while the gossip layer sees nothing.
//
// Topic rotation: `rotating_topic` = HMAC(room_key, day) — a kicked
// member loses the key and can no longer follow the daily topic name;
// yesterday's topic can't be replayed into today's.

const V2_MAGIC: &[u8; 4] = b"NRV2";

fn v2_seal_key(room_key: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"noid-room-v2-seal"), room_key);
    let mut k = [0u8; 32];
    let _ = hk.expand(b"v2", &mut k);
    k
}

/// Rotating gossipsub topic for a room on `day` —
/// `noid-rt-<hex(HMAC(room_key, "noid-room-topic" || day))[:32]>`.
pub fn rotating_topic(room_key: &[u8; 32], day: u64) -> String {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"noid-room-topic"), room_key);
    let mut t = [0u8; 32];
    let _ = hk.expand(&day.to_be_bytes(), &mut t);
    format!("noid-rt-{}", hex::encode(&t[..16]))
}

/// Seal a V1 envelope inside the V2 outer layer — transit sees `NRV2 ||
/// nonce || ct` and nothing else.
pub fn seal_v2(
    key: &[u8; 32],
    room_id: &str,
    keypair: &libp2p::identity::Keypair,
    msg_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let inner = seal(key, room_id, keypair, msg_id, plaintext)?;
    let inner_json = serde_json::to_vec(&inner)?;
    let mut sk = v2_seal_key(key);
    let cipher = Aes256Gcm::new_from_slice(&sk).map_err(|e| anyhow!("v2 key: {}", e))?;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), inner_json.as_ref())
        .map_err(|e| anyhow!("v2 encrypt: {}", e))?;
    sk.zeroize();
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(V2_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap the V2 outer seal — returns the inner `RoomEnvelope` JSON so
/// the caller runs the standard V1 pipeline (signature + freshness +
/// decrypt). `None` when the magic is absent, the blob is malformed, or
/// the outer AEAD fails (non-member or tampered).
pub fn unwrap_v2(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 4 + 12 + 16 || &blob[..4] != V2_MAGIC {
        return None;
    }
    let mut sk = v2_seal_key(key);
    let cipher = Aes256Gcm::new_from_slice(&sk).ok()?;
    let nonce = Nonce::from(<[u8; 12]>::try_from(&blob[4..16]).ok()?);
    let inner = cipher.decrypt(&nonce, &blob[16..]).ok();
    sk.zeroize();
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = RoomKey::generate();
        let room_id = key.room_id();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let env = seal(&key.0, &room_id, &kp, "m1", b"hello room").unwrap();
        let pt = open(&key.0, &room_id, &env).unwrap();
        assert_eq!(pt, b"hello room");
    }

    #[test]
    fn wrong_room_key_fails() {
        let k1 = RoomKey::generate();
        let k2 = RoomKey::generate();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let env = seal(&k1.0, &k1.room_id(), &kp, "m1", b"x").unwrap();
        assert!(open(&k2.0, &k1.room_id(), &env).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = RoomKey::generate();
        let room_id = key.room_id();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let mut env = seal(&key.0, &room_id, &kp, "m1", b"x").unwrap();
        env.ciphertext[20] ^= 1;
        assert!(open(&key.0, &room_id, &env).is_err());
    }

    #[test]
    fn forged_sender_rejected() {
        let key = RoomKey::generate();
        let room_id = key.room_id();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let mut env = seal(&key.0, &room_id, &kp, "m1", b"x").unwrap();
        env.sender_peer_id = libp2p::PeerId::random().to_string();
        assert!(open(&key.0, &room_id, &env).is_err());
    }

    #[test]
    fn v2_roundtrip_hides_envelope() {
        let key = RoomKey::generate();
        let room_id = key.room_id();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let blob = seal_v2(&key.0, &room_id, &kp, "m1", b"secret").unwrap();
        assert!(blob.starts_with(b"NRV2"));
        // Wire bytes expose no JSON fields — sender/ts invisible to transit.
        assert!(!blob.windows(4).any(|w| w == b"msg_".as_slice()));
        let inner = unwrap_v2(&key.0, &blob).unwrap();
        let env: RoomEnvelope = serde_json::from_slice(&inner).unwrap();
        let pt = open(&key.0, &room_id, &env).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn v2_wrong_key_silent_drop() {
        let k1 = RoomKey::generate();
        let k2 = RoomKey::generate();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let blob = seal_v2(&k1.0, &k1.room_id(), &kp, "m1", b"x").unwrap();
        assert!(unwrap_v2(&k2.0, &blob).is_none());
        // Non-V2 input returns None, not an error.
        assert!(unwrap_v2(&k1.0, b"{}").is_none());
    }

    #[test]
    fn rotating_topic_derives_and_rotates() {
        let key = RoomKey::generate();
        let t1 = rotating_topic(&key.0, 20000);
        let t2 = rotating_topic(&key.0, 20001);
        assert!(t1.starts_with("noid-rt-"));
        assert_ne!(t1, t2);
        // Same key + day → deterministic; different key → different topic.
        assert_eq!(t1, rotating_topic(&key.0, 20000));
        let other = RoomKey::generate();
        assert_ne!(t1, rotating_topic(&other.0, 20000));
    }
}
