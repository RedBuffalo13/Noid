//! Domain-separated subkeys derived from the login master key (audit S14).
//!
//! Historically a single AES-256-GCM master key encrypted every domain:
//! message blobs, DB text fields, audit-log details and key envelopes.
//! That lets an attacker with write access to the database relocate a
//! ciphertext between domains — e.g. a `NOIDKEY1` private-key envelope
//! pasted into `messages.content` decrypts via `get_chat_messages`,
//! turning the UI into a decryption oracle.
//!
//! `derive_domain_key` produces an independent key per domain via
//! HKDF-SHA256: `K_dom = HKDF(master, "noid-domain:<dom>")`. New writes are
//! tagged with a per-domain magic so decryption never needs to guess; the
//! legacy master-key read path is kept only to remain compatible with
//! data written before the split, and each format migrates forward on
//! rewrite.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive the AES-256 key for `domain` from the master key.
/// `domain` is a short stable identifier ("msg", "db-field", "audit",
/// "keystore") — changing it yields an unrelated key.
pub fn derive_domain_key(master: &[u8; 32], domain: &str) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let info = format!("noid-domain:{}", domain);
    let mut key = [0u8; 32];
    // HKDF expand to a 32-byte output cannot fail (output <= 255*32).
    hkdf.expand(info.as_bytes(), &mut key)
        .expect("HKDF expand to 32 bytes");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_differ() {
        let master = [42u8; 32];
        let a = derive_domain_key(&master, "msg");
        let b = derive_domain_key(&master, "db-field");
        let c = derive_domain_key(&master, "msg");
        assert_ne!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, master);
    }
}
