//! Mailbox abuse guard — in-memory rate limits and quotas for the mailbox
//! store/forward service. Without these, any peer could fill a mailbox node
//! with unbounded envelopes or harvest other recipients' mail.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Max envelope size accepted for storage (a chat message is far below this).
pub const MAX_ENVELOPE_BYTES: usize = 4096;
/// Max envelopes a single sender may park for one recipient.
pub const MAX_PER_SENDER_PER_RECIPIENT: i64 = 50;
/// Max total envelopes held for one recipient.
pub const MAX_PER_RECIPIENT: i64 = 200;
/// Store requests allowed per peer per minute (token bucket).
const STORE_TOKENS_PER_MINUTE: u32 = 10;
/// S20: Retrieve/Delete had no limit — a hostile peer could drain ~800KiB
/// per response continuously. Retrieval is legitimately periodic (~5min),
/// so the bucket is small but non-zero; deletes track message volume.
const RETRIEVE_TOKENS_PER_MINUTE: u32 = 6;
const DELETE_TOKENS_PER_MINUTE: u32 = 250;

pub struct MailboxGuard {
    /// peer_id → (remaining tokens, window start)
    buckets: HashMap<String, (u32, Instant)>,
    retrieve_buckets: HashMap<String, (u32, Instant)>,
    delete_buckets: HashMap<String, (u32, Instant)>,
}

/// DB31: a flood of distinct peer ids must not grow the bucket maps
/// without bound — entries idle for > 2 windows are dead weight.
const MAX_BUCKETS: usize = 10_000;

fn take_token(buckets: &mut HashMap<String, (u32, Instant)>, peer: &str, per_minute: u32) -> bool {
    let now = Instant::now();
    if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(peer) {
        // Evict stale entries first; if the map is still full of recently
        // active peers, deny the newcomer (fail-closed under flood).
        buckets.retain(|_, (_, window)| now.duration_since(*window) < Duration::from_secs(120));
        if buckets.len() >= MAX_BUCKETS {
            return false;
        }
    }
    let entry = buckets.entry(peer.to_string()).or_insert((per_minute, now));
    if now.duration_since(entry.1) >= Duration::from_secs(60) {
        *entry = (per_minute, now);
    }
    if entry.0 == 0 {
        return false;
    }
    entry.0 -= 1;
    true
}

impl Default for MailboxGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl MailboxGuard {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            retrieve_buckets: HashMap::new(),
            delete_buckets: HashMap::new(),
        }
    }

    /// Token bucket: `STORE_TOKENS_PER_MINUTE` Store requests per peer.
    pub fn allow_store(&mut self, peer: &str) -> bool {
        take_token(&mut self.buckets, peer, STORE_TOKENS_PER_MINUTE)
    }

    /// S20: `RETRIEVE_TOKENS_PER_MINUTE` Retrieve requests per peer.
    pub fn allow_retrieve(&mut self, peer: &str) -> bool {
        take_token(&mut self.retrieve_buckets, peer, RETRIEVE_TOKENS_PER_MINUTE)
    }

    /// S20: `DELETE_TOKENS_PER_MINUTE` Delete requests per peer.
    pub fn allow_delete(&mut self, peer: &str) -> bool {
        take_token(&mut self.delete_buckets, peer, DELETE_TOKENS_PER_MINUTE)
    }

    pub fn envelope_size_ok(content: &[u8]) -> bool {
        content.len() <= MAX_ENVELOPE_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_allows_then_blocks() {
        let mut g = MailboxGuard::new();
        for _ in 0..STORE_TOKENS_PER_MINUTE {
            assert!(g.allow_store("peer1"));
        }
        assert!(!g.allow_store("peer1"));
        // Other peers unaffected
        assert!(g.allow_store("peer2"));
    }

    #[test]
    fn envelope_size_cap() {
        assert!(MailboxGuard::envelope_size_ok(&vec![0u8; 4096]));
        assert!(!MailboxGuard::envelope_size_ok(&vec![0u8; 4097]));
    }
}
