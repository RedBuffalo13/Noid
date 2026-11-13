//! META-03: what a blinded DHT descriptor query is for.
//!
//! `pending_blind_queries` tags every `get_record` issued against a
//! `blind_record_key` (peer-scoped descriptor) or an Argon2id-blinded
//! username key, so the result handler knows how to unwrap and which
//! event to emit.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindKind {
    /// Encrypted 1024 B descriptor holding the peer's signed PrekeyBundle.
    Prekey,
    /// Encrypted 1024 B descriptor holding the peer's SignedMailboxRecord.
    Mailbox,
    /// Argon2id-blinded username key — value stays the signed JSON record;
    /// only the lookup key is scraped-proof.
    Username,
}
