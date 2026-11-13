//! CGNAT dial assistance: mutual hole-punch + rendezvous announce.
//!
//! Triggered whenever we intentionally dial a peer (invite, contact connect,
//! fast redial). Two side effects ride along with `swarm.dial`:
//! 1. [`crate::p2p::punch_assist::spawn_udp_punch_burst`] sends UDP knocks
//!    from our QUIC listener socket toward the peer's external addr — our
//!    carrier CGNAT opens the return pinhole for their simultaneous dial.
//! 2. [`crate::p2p::cgnat_rendezvous::announce_and_poll_rendezvous`] publishes
//!    our STUN-mapped port into the target's Mainline-DHT rendezvous slot so
//!    a seed node behind CGNAT learns our coordinates and punches back.
//!    Announce runs only in `Direct` privacy — `RelayedOnly` must not leak
//!    our external endpoint into a public DHT.

use libp2p::Multiaddr;
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Fire hole-punch + rendezvous-announce side effects for a dial of `addr`.
    /// Discovered rendezvous peers are forwarded into `rv_tx` (consumed by the
    /// event loop, which punches/dials them back).
    pub(crate) fn assist_cgnat_dial(
        &mut self,
        addr: &Multiaddr,
        rv_tx: &mpsc::Sender<Vec<SocketAddr>>,
    ) {
        // SEC-1111-03: UDP punches and Mainline-DHT announces ride the
        // direct path only — under RelayedOnly/proxy/tor_only they would
        // leak the real IP exactly when the user opted out of it.
        if !self.direct_net_allowed() {
            return;
        }
        if let Some(sa) = crate::p2p::punch_assist::extract_wan_socket_addr(addr) {
            crate::p2p::punch_assist::spawn_udp_punch_burst(sa, true);
        }

        let (Some(target_peer), Some(mapping)) = (
            crate::p2p::terminal_peer_id::terminal_peer_id(addr),
            libp2p_quic::stun_hook::observed_stun_mapping(),
        ) else {
            return;
        };
        // Announce slots: the invite's one-time rv slot when present (the
        // public PeerId never names a slot), plus the contact's persistent
        // daily rv-v2 slot when their public key is known — the latter is
        // what re-finds a contact after restarts without a new invite.
        let mut slots: Vec<String> = vec![self
            .pending_rv
            .get(&target_peer)
            .cloned()
            .unwrap_or_else(|| target_peer.to_string())];
        if let Some(pk) = self.peer_pubkeys.get(&target_peer) {
            slots.push(crate::p2p::cgnat_rendezvous::daily_slot_label(pk));
        }
        let my_id = self.peer_id.to_string();
        let my_port = mapping.external_addr.port();
        let tx = rv_tx.clone();
        tokio::task::spawn_blocking(move || {
            let mut peers = Vec::new();
            for slot in slots {
                for p in crate::p2p::cgnat_rendezvous::announce_and_poll_rendezvous(
                    &slot, &my_id, my_port,
                ) {
                    if !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            }
            let _ = tx.try_send(peers);
        });
    }
}
