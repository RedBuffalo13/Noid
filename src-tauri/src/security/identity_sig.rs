//! Ed25519 identity signatures for DHT records.
//!
//! Every self-published DHT record (prekey bundle, mailbox pointer, username
//! record) is signed by the owner's libp2p identity key. Readers verify the
//! signature against the public key embedded in the owner `PeerId` — a
//! malicious DHT peer cannot forge or overwrite them.

use anyhow::{anyhow, Result};
use libp2p::identity::{Keypair, PublicKey};
use libp2p::PeerId;

/// Extract the Ed25519 public key embedded in an identity-multihash PeerId.
/// Returns None for hash-based PeerIds (sha256 etc.) — we always use inlined
/// Ed25519 identities, so a non-inline PeerId cannot verify records.
pub fn pubkey_from_peer_id(peer_id: &str) -> Result<PublicKey> {
    let pid: PeerId = peer_id
        .parse()
        .map_err(|e| anyhow!("Invalid peer id '{}': {}", peer_id, e))?;
    let mh = libp2p::multihash::Multihash::<64>::from_bytes(&pid.to_bytes())
        .map_err(|e| anyhow!("Invalid peer id multihash: {}", e))?;
    if mh.code() != 0 {
        return Err(anyhow!("Peer id is not an inlined identity key"));
    }
    PublicKey::try_decode_protobuf(mh.digest())
        .map_err(|e| anyhow!("Cannot decode public key from peer id: {}", e))
}

/// Sign `payload` with the node's identity keypair.
pub fn sign_payload(keypair: &Keypair, payload: &[u8]) -> Result<Vec<u8>> {
    keypair
        .sign(payload)
        .map_err(|e| anyhow!("Identity signing failed: {}", e))
}

/// Verify `signature` over `payload` against the public key embedded in
/// `owner_peer_id`. Any failure — bad peer id, non-inline key, invalid
/// signature — returns false; callers must treat unverifiable records as
/// hostile and ignore them.
pub fn verify_payload(owner_peer_id: &str, payload: &[u8], signature: &[u8]) -> bool {
    match pubkey_from_peer_id(owner_peer_id) {
        Ok(pk) => pk.verify(payload, signature),
        Err(e) => {
            log::warn!("Cannot verify record for {}: {}", owner_peer_id, e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate_ed25519();
        let peer_id = PeerId::from(kp.public()).to_string();
        let payload = b"record payload".to_vec();
        let sig = sign_payload(&kp, &payload).unwrap();
        assert!(verify_payload(&peer_id, &payload, &sig));
    }

    #[test]
    fn tampered_payload_rejected() {
        let kp = Keypair::generate_ed25519();
        let peer_id = PeerId::from(kp.public()).to_string();
        let sig = sign_payload(&kp, b"original").unwrap();
        assert!(!verify_payload(&peer_id, b"tampered", &sig));
    }

    #[test]
    fn wrong_owner_rejected() {
        let kp = Keypair::generate_ed25519();
        let other = PeerId::from(Keypair::generate_ed25519().public()).to_string();
        let sig = sign_payload(&kp, b"payload").unwrap();
        let peer_id = PeerId::from(kp.public()).to_string();
        // Valid signature, but claimed owner is someone else.
        assert!(!verify_payload(&other, b"payload", &sig));
        assert!(verify_payload(&peer_id, b"payload", &sig));
    }
}
