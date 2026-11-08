//! B5: `NetworkChanged` handler — extracted from the event loop so the
//! debounce logic at the call site stays a few lines.
//!
//! The interface that owned every addr and socket just died (Wi-Fi ↔ LTE,
//! Doze wake, VPN switch). On Android the old TCP/WS sockets stay
//! ESTABLISHED-but-dead for ~60s — outbound requests routed onto them burn
//! full timeouts while the swarm still reports the peer "connected".

use libp2p::Multiaddr;

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Full network-change reset: drop stale external addrs, clear
    /// reservation/backoff bookkeeping, close non-QUIC conns, re-dial seeds
    /// and re-reserve. Called by the event loop (debounced — see B5).
    pub(crate) fn on_network_changed(&mut self) {
        // 1) All external addrs are stale — direct ones were bound to the
        //    dead interface, relayed ones rode reservations on conns that
        //    are dying too.
        let stale: Vec<Multiaddr> = self.external_addrs.to_vec();
        for addr in &stale {
            self.swarm.remove_external_address(addr);
        }
        self.external_addrs.clear();
        // 2) Reservation bookkeeping belonged to the dead interface —
        //    clearing it lets refresh_reservations re-issue RESERVE instead
        //    of skipping a phantom "still held" reservation (the listener on
        //    the dead conn never revives).
        self.reserved_relays.clear();
        self.pending_reservations.clear();
        self.reservation_denied.clear();
        self.relayed_addrs.clear();
        self.relayed_listener_refs.clear();
        self.mailbox_record_peer = None;
        // 3) Backoffs / dead-addr marks observed on the dead network would
        //    suppress redials on the new one — clear them all.
        self.dial_backoffs.clear();
        self.addr_failures.clear();
        self.dead_addrs.clear();
        self.ping_failures.clear();
        self.bootstrap_retry_state.clear();
        // 4) Close connections that cannot migrate: TCP/WS sockets bound to
        //    the dead interface are zombies. QUIC keeps its conn-ID
        //    migration path — if migration fails, ping failure handling
        //    reaps it within ~30s anyway.
        let zombie: Vec<libp2p::swarm::ConnectionId> = self
            .conn_quic
            .values()
            .flat_map(|m| m.iter())
            .filter(|(_, quic)| !**quic)
            .map(|(id, _)| *id)
            .collect();
        for id in &zombie {
            let _ = self.swarm.close_connection(*id);
        }
        log::info!(
            "Network changed — dropped {} stale external addr(s), closing {} non-QUIC conn(s)",
            stale.len(),
            zombie.len()
        );
        // 5) Re-dial bootstrap seeds immediately so the relay book refills
        //    on the new interface; then re-reserve and re-discover (each
        //    accepted reservation republishes the mailbox record, A7).
        self.retry_bootstrap_dials();
        self.refresh_reservations();
        self.discover_relays();
    }
}
