//! Per-peer dial backoff.
//!
//! Without it, every failed send / ConnectToPeer / Kademlia result triggers
//! an immediate redial — an offline contact produces a dial storm and a WARN
//! per attempt. After each `OutgoingConnectionError` the peer is marked
//! unreachable for an exponentially growing window (30s → 5min cap); during
//! the window `send_request` fails fast into the pending/mailbox path and
//! explicit dials are skipped. A successful `ConnectionEstablished` clears
//! the record entirely.

use libp2p::PeerId;
use std::time::{Duration, Instant};

use crate::p2p::node::P2PNode;

/// Cooldown after the first failed dial.
const INITIAL_BACKOFF: Duration = Duration::from_secs(30);
/// Longest cooldown — an unreachable peer is retried at most every 5 min.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// One peer's backoff state: consecutive failures + next allowed dial time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DialBackoff {
    failures: u32,
    next_allowed: Instant,
}

impl DialBackoff {
    fn next_delay(failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(10);
        let secs = INITIAL_BACKOFF.as_secs().saturating_mul(1u64 << shift);
        let base = secs.min(MAX_BACKOFF.as_secs());
        // ±20% jitter — synchronized failures across peers would otherwise
        // re-dial in lockstep bursts after every shared outage.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let jitter = (nanos % 41) as i64 - 20; // -20..=20 percent
        let jittered = base as i64 * (100 + jitter) / 100;
        Duration::from_secs(jittered.max(1) as u64)
    }
}

impl P2PNode {
    /// True while the peer is inside a backoff window — do not dial.
    pub(crate) fn dial_is_backed_off(&self, peer: &PeerId) -> bool {
        self.dial_backoffs
            .get(peer)
            .map(|b| b.next_allowed > Instant::now())
            .unwrap_or(false)
    }

    /// Record a dial failure — grows the backoff exponentially.
    /// Returns the consecutive-failure count so callers can escalate (e.g.
    /// purge the peer from Kademlia entirely after repeated failures).
    pub(crate) fn record_dial_failure(&mut self, peer: &PeerId) -> u32 {
        let failures = self
            .dial_backoffs
            .get(peer)
            .map(|b| b.failures + 1)
            .unwrap_or(1);
        let delay = DialBackoff::next_delay(failures);
        self.dial_backoffs.insert(
            *peer,
            DialBackoff {
                failures,
                next_allowed: Instant::now() + delay,
            },
        );
        log::debug!(
            "Dial backoff for {}: {}s (failure #{})",
            peer,
            delay.as_secs(),
            failures
        );
        failures
    }

    /// Clear the record — called on a successful connection.
    pub(crate) fn clear_dial_backoff(&mut self, peer: &PeerId) {
        self.dial_backoffs.remove(peer);
    }
}
