//! OPT-R05: contact-key ECDH fallback for mailbox envelopes — used when
//! no ratchet session exists yet (typed payloads, pre-ratchet plain
//! content). Was spelled out three times in the MailboxNodeFound arm.

use crate::db::Database;
use crate::security::DHTCipher;

/// Look up the contact's stored public key and wrap `content` in an
/// ECDH envelope for it. Returns `None` when there is no DHT cipher, no
/// stored key, a malformed key length, or encryption/serialization
/// fails — the caller decides whether that keeps the row pending.
pub async fn encrypt_mailbox_ecdh(
    db: &Database,
    dht_cipher: Option<&DHTCipher>,
    peer_id: &str,
    content: &str,
) -> Option<Vec<u8>> {
    let key = db.get_contact_public_key(peer_id).await.ok().flatten()?;
    let cipher = dht_cipher?;
    if key.len() != 32 {
        return None;
    }
    let mut kb = [0u8; 32];
    kb.copy_from_slice(&key);
    cipher
        .encrypt_for_recipient(content.as_bytes(), &x25519_dalek::PublicKey::from(kb))
        .ok()
        .and_then(|m| serde_json::to_vec(&m).ok())
}
