//! Token-bucket rate limiters for the relay server behaviour.
//!
//! `libp2p-relay` ships conservative defaults (30/hr per peer, 60/hr per IP
//! for both reservations and circuits) and does not export the bucket
//! implementation — only the [`RateLimiter`] trait. A client recovering from
//! a connection flap re-dials a circuit per send attempt and drains the
//! 30-token hourly bucket in minutes, after which every `CIRCUIT` is denied
//! until tokens slowly refill — the observed "several failed cycles" before
//! delivery. These limiters keep the same token-bucket semantics with limits
//! sized for a small private messenger network.

use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::PeerId;
use libp2p::relay::RateLimiter;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

/// Token bucket keyed by an arbitrary id (peer id or source IP).
struct TokenBucket<Id> {
    limit: u32,
    interval: Duration,
    refill_schedule: VecDeque<(Instant, Id)>,
    buckets: HashMap<Id, u32>,
}

impl<Id: Eq + PartialEq + Hash + Clone> TokenBucket<Id> {
    fn new(limit: NonZeroU32, interval: Duration) -> Self {
        debug_assert!(!interval.is_zero());
        Self {
            limit: limit.into(),
            interval,
            refill_schedule: VecDeque::new(),
            buckets: HashMap::new(),
        }
    }

    fn try_next(&mut self, id: Id, now: Instant) -> bool {
        self.refill(now);
        match self.buckets.get_mut(&id) {
            Some(balance) => match balance.checked_sub(1) {
                Some(rest) => {
                    *balance = rest;
                    true
                }
                None => false,
            },
            None => {
                self.buckets.insert(id.clone(), self.limit - 1);
                self.refill_schedule.push_back((now, id));
                true
            }
        }
    }

    fn refill(&mut self, now: Instant) {
        loop {
            match self.refill_schedule.front() {
                Some((last_refill, _)) if now.duration_since(*last_refill) >= self.interval => {}
                _ => return,
            }
            let (last_refill, id) = match self.refill_schedule.pop_front() {
                Some(item) => item,
                None => return,
            };
            if let Some(balance) = self.buckets.get_mut(&id) {
                if *balance < self.limit {
                    *balance += 1;
                    self.refill_schedule.push_back((now, id));
                }
            }
            let _ = last_refill;
        }
    }
}

fn multiaddr_to_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(addr) => Some(addr.into()),
        Protocol::Ip6(addr) => Some(addr.into()),
        _ => None,
    })
}

/// Per-peer-token bucket limiter.
pub fn per_peer(limit: u32, interval: Duration) -> Box<dyn RateLimiter> {
    let mut bucket = TokenBucket::new(
        NonZeroU32::new(limit.max(1)).expect("limit >= 1"),
        interval,
    );
    Box::new(move |peer_id: PeerId, _addr: &Multiaddr, now: Instant| {
        bucket.try_next(peer_id, now)
    })
}

/// Per-source-IP token bucket limiter.
pub fn per_ip(limit: u32, interval: Duration) -> Box<dyn RateLimiter> {
    let mut bucket = TokenBucket::new(
        NonZeroU32::new(limit.max(1)).expect("limit >= 1"),
        interval,
    );
    Box::new(move |_peer_id: PeerId, addr: &Multiaddr, now: Instant| {
        multiaddr_to_ip(addr)
            .map(|ip| bucket.try_next(ip, now))
            .unwrap_or(true)
    })
}
