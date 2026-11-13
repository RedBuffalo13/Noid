//! P2PNode DHT/peer-cache helper methods — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use libp2p::{multiaddr::Protocol, PeerId};
use std::collections::HashSet;

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Ephemeral node for tests — fresh random keys, nothing written to disk.
    /// Production code never uses this: real nodes are created via
    /// `new_with_keys` after the key store is unlocked by a successful login.
    pub(crate) fn set_contact_peers(&mut self, peers: HashSet<PeerId>) {
        self.contact_peers = peers;
    }

    /// Record a message id in the replay cache. When the cache exceeds 10k
    /// entries the oldest 5k are evicted — never a full clear, which would
    /// reopen the replay window for everything seen before.
    pub(crate) fn mark_seen(&mut self, id: &str) {
        self.seen_message_ids.insert(id.to_string());
        self.seen_order.push_back(id.to_string());
        if self.seen_order.len() > 10_000 {
            let overflow = self.seen_order.len() - 5_000;
            for _ in 0..overflow {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen_message_ids.remove(&old);
                }
            }
            log::debug!("Evicted {} oldest ids from replay cache", overflow);
        }
    }

    /// Park an inbound request's response channel until the app layer
    /// acknowledges durable processing via `P2PCommand::AckReceived`
    /// (TI-1). Entries older than 30s — past the sender's 10s response
    /// timeout — are swept on insert; the map is capped at 512.
    pub(crate) fn park_app_ack(
        &mut self,
        peer_id: String,
        message_id: String,
        channel: libp2p::request_response::ResponseChannel<crate::p2p::types::NoidResponse>,
    ) {
        const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30);
        const MAX_PARKED: usize = 512;
        let now = std::time::Instant::now();
        self.pending_app_acks
            .retain(|_, (_, parked_at)| now.duration_since(*parked_at) < MAX_AGE);
        if self.pending_app_acks.len() >= MAX_PARKED {
            // Channel dropped — the sender times out and retries.
            log::warn!(
                "pending_app_acks full ({} parked) — dropping inbound request {}",
                MAX_PARKED,
                message_id
            );
            return;
        }
        self.pending_app_acks
            .insert((peer_id, message_id), (channel, now));
    }

    /// Persist the peer cache eagerly while the learned set is still small:
    /// the first peers/relay are exactly what makes warm start work, and a
    /// session shorter than the 30s flush tick must not lose them. Churn
    /// beyond the early set is flushed on the timer.
    pub(crate) fn maybe_flush_peer_cache(&mut self) {
        if self.peer_cache_dirty && self.peer_cache.peers.len() <= 10 {
            self.peer_cache
                .save(&self.data_dir.clone(), self.field_cipher.as_deref());
            self.peer_cache_dirty = false;
        }
    }

    /// Seed Kademlia and dial peers remembered from the previous session.
    /// Called once at startup alongside `bootstrap` — relays are dialed first,
    /// so a returning node rejoins its "circle" without needing a new invite.
    /// D13: write a local DHT fallback copy with a 24h expiry — records
    /// must not outlive their network TTL just because they are ours.
    pub(crate) fn local_dht_put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.local_dht_records_ts
            .insert(key.clone(), std::time::Instant::now());
        self.local_dht_records.insert(key, value);
    }

    /// B2: whether Kademlia's routing table holds at least one peer.
    /// With zero routing peers every `put_record` fails instantly —
    /// publishing attempts must wait for the first RoutingUpdated instead
    /// of storming QuorumFailed retries.
    pub(crate) fn routing_has_peers(&mut self) -> bool {
        self.swarm
            .behaviour_mut()
            .kademlia
            .kbuckets()
            .any(|b| b.iter().next().is_some())
    }

    /// DHT-02: publish a record, tracking the query for retry — on a
    /// synchronous refusal (empty routing table at cold start) the record
    /// is parked in `deferred_dht_puts` and retried by the status tick.
    pub(crate) fn queue_dht_put(&mut self, record: libp2p::kad::Record) {
        match self
            .swarm
            .behaviour_mut()
            .kademlia
            .put_record(record.clone(), libp2p::kad::Quorum::One)
        {
            Ok(qid) => {
                self.pending_prekey_puts.insert(qid, (record, 0));
            }
            Err(e) => {
                if self.deferred_dht_puts.len() < 32 {
                    self.deferred_dht_puts.push(record);
                }
                log::warn!(
                    "DHT put deferred — no routing peers yet ({} queued): {}",
                    self.deferred_dht_puts.len(),
                    e
                );
            }
        }
    }

    /// DHT-02: retry parked records — drained once Kademlia actually has
    /// peers to seed a query. Records that STILL fail stay queued; the
    /// put_record cap (32) bounds the backlog.
    /// B2: skip the drain entirely while the routing table is empty —
    /// every attempt would just re-park and log another QuorumFailed.
    pub(crate) fn drain_deferred_dht_puts(&mut self) {
        if self.deferred_dht_puts.is_empty() || !self.routing_has_peers() {
            return;
        }
        let pending = std::mem::take(&mut self.deferred_dht_puts);
        for record in pending {
            match self
                .swarm
                .behaviour_mut()
                .kademlia
                .put_record(record.clone(), libp2p::kad::Quorum::One)
            {
                Ok(qid) => {
                    self.pending_prekey_puts.insert(qid, (record, 0));
                    log::info!("Deferred DHT record finally published");
                }
                Err(_) => self.deferred_dht_puts.push(record),
            }
        }
    }

    /// D13: read a local DHT fallback copy; returns `None` once the entry
    /// is older than the 24h record TTL (and prunes it). Entries written
    /// without a timestamp (tests) never expire.
    pub(crate) fn local_dht_get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        const TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
        let expired = self
            .local_dht_records_ts
            .get(key)
            .is_some_and(|ts| ts.elapsed() > TTL);
        if expired {
            self.local_dht_records.remove(key);
            self.local_dht_records_ts.remove(key);
            return None;
        }
        self.local_dht_records.get(key).cloned()
    }

    pub fn seed_from_peer_cache(&mut self) {
        for (peer_id, addr) in self.peer_cache.startup_peers() {
            if peer_id == self.peer_id {
                continue;
            }
            // Cached addrs may be stale or malformed (nested circuits, an
            // addr terminating at a different peer, loopback/LAN hints) —
            // classify before dialing.
            if matches!(
                crate::p2p::classify_peer_addr::classify_peer_addr(&addr, &peer_id),
                crate::p2p::addr_class::AddrClass::Malformed
                    | crate::p2p::addr_class::AddrClass::Local
            ) {
                continue;
            }
            if self.is_own_listen_addr(&addr) {
                continue;
            }
            if !self.dial_allowed(&addr) {
                continue;
            }
            // D13: skip addrs that already proved dead this session —
            // otherwise every startup wastes a dial on each.
            if self.is_dead_addr(&addr) {
                continue;
            }
            // Cached relays re-join known_relays so the ConnectionEstablished
            // handler requests a fresh reservation on reconnect.
            let is_relay = self
                .peer_cache
                .peers
                .iter()
                .any(|p| p.peer_id == peer_id.to_string() && p.is_relay);
            // A cached circuit addr for a relay peer is poison from the
            // old relay→relay reservation chains — a relay is only useful
            // reached directly.
            if is_relay
                && addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
            {
                continue;
            }
            self.register_peer_addr(peer_id, addr.clone(), "cache", false);
            if is_relay
                && !self.known_relays.iter().any(|(p, _)| *p == peer_id)
            {
                self.known_relays.push((peer_id, addr.clone()));
            }
            // TR-06: warm-start dials are reserved for RELAYS — reconnecting
            // the reservation path is what makes the node reachable again.
            // Ordinary cached peers only feed the address books here: a
            // startup dial storm across every stale contact addr burned
            // dial-backoff budgets and produced a burst of failures on
            // mobile launch. Contact dials happen on demand (send /
            // reconnect_to_contacts).
            if !is_relay {
                continue;
            }
            // Always bind the dial to the cached peer id: a bare addr yields
            // OutgoingConnectionError{peer_id: None}, which skips eviction and
            // backoff — the dead addr is then retried on every startup.
            let dial_addr = if addr.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                addr
            } else {
                addr.with(Protocol::P2p(peer_id))
            };
            if let Some(opts) =
                crate::p2p::dial_opts::dial_opts(Some(peer_id), dial_addr)
            {
                let _ = self.swarm.dial(opts);
            }
        }
    }

}
