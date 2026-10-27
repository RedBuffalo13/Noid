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
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Symmetric room key. `room_id` is a fingerprint — safe to share as a topic.
pub struct RoomKey(pub [u8; 32]);

impl RoomKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
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
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
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
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("room envelope decrypt failed"))
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
}
