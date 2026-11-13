//! Transport-policy helpers for the ConnectionEstablished arm — relayed/
//! direct bookkeeping and QUIC pinning. Behaviour-preserving extraction
//! (Q04/A5); bodies moved verbatim, only the signatures are new.

use super::*;

impl P2PNode {
    pub(crate) fn conn_transport_branch(
        &mut self,
        peer_id: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        endpoint: &libp2p::core::ConnectedPoint,
    ) {
                        if endpoint.is_relayed() {
                            // Track first, decide second: close_connection is
                            // async — until ConnectionClosed the conn still sits
                            // in the pool and RESERVE dedup can land on it.
                            // request_reservation defers while this set is
                            // non-empty.
                            self.relayed_conn_ids
                                .entry(peer_id)
                                .or_default()
                                .insert(connection_id);
                            // A relayed conn to a reservation-eligible relay is
                            // only safe to close when a DIRECT conn to that
                            // peer already exists — every noid node advertises
                            // HOP, so "known relay" here is any connected peer,
                            // and for a CGNAT-locked peer the circuit is the
                            // ONLY data path. Killing it unconditionally
                            // stranded relayed peers entirely: conns flapped on
                            // establish and pending traffic dead-ended until a
                            // direct conn happened to form. With no direct
                            // path we keep the circuit and dial a direct
                            // upgrade in parallel; the direct-connection arm
                            // above closes the circuit once one lands. The
                            // nested-circuit hazard (RESERVE deduping onto a
                            // relayed conn) stays covered — request_reservation
                            // defers while `relayed_conn_ids` is non-empty.
                            let is_known_relay =
                                self.known_relays.iter().any(|(p, _)| *p == peer_id);
                            if is_known_relay {
                                if self.direct_conns.get(&peer_id).copied().unwrap_or(0) > 0 {
                                    // Grace close, not immediate (TR-08):
                                    // the RESERVE-dedup hazard stays
                                    // covered because the id remains in
                                    // relayed_conn_ids until
                                    // ConnectionClosed, and the fire-time
                                    // revalidation saves the circuit if the
                                    // direct conn dies inside the window.
                                    log::info!(
                                        "Scheduling close of relayed conn to known relay {} — direct conn available",
                                        peer_id
                                    );
                                    self.pending_conn_close.push((
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20),
                                        peer_id,
                                        connection_id,
                                    ));
                                } else if !self.dial_is_backed_off(&peer_id) {
                                    log::info!(
                                        "Relayed conn to {} is the only path — keeping; dialing direct upgrade",
                                        peer_id
                                    );
                                    // TR-02: dial_opts_multi lifts the
                                    // DisconnectedAndNotDialing condition so
                                    // the upgrade runs over the live circuit.
                                    let direct = self.direct_addrs_of(&peer_id);
                                    if !direct.is_empty() {
                                        let _ = self.swarm.dial(
                                            crate::p2p::dial_opts::dial_opts_multi(
                                                peer_id, direct,
                                            ),
                                        );
                                    }
                                }
                            }
                        } else {
                            *self.direct_conns.entry(peer_id).or_insert(0) += 1;
                            // A direct conn to a reservation-eligible relay
                            // makes any relayed conns to it redundant AND
                            // dangerous: a RESERVE issued now deduplicates
                            // onto an arbitrary existing conn — a relayed one
                            // would yield a nested-circuit listen addr.
                            // Grace close (TR-08): the ids stay in
                            // relayed_conn_ids so request_reservation keeps
                            // deferring until ConnectionClosed confirms them
                            // gone.
                            if self.known_relays.iter().any(|(p, _)| *p == peer_id) {
                                if let Some(ids) = self.relayed_conn_ids.get(&peer_id) {
                                    let deadline = tokio::time::Instant::now()
                                        + tokio::time::Duration::from_secs(20);
                                    for id in ids.iter().copied().collect::<Vec<_>>() {
                                        log::debug!(
                                            "Scheduling close of redundant relayed conn {:?} to relay {}",
                                            id, peer_id
                                        );
                                        self.pending_conn_close.push((deadline, peer_id, id));
                                    }
                                }
                            }
                        }
    }

    /// QUIC pinning for the fresh conn. Returns `true` when this conn was
    /// scheduled/closed inside — the caller must then skip PeerConnected
    /// (EL-08). `is_quic` is the precomputed transport flag of `endpoint`.
    pub(crate) fn conn_pin_quic(
        &mut self,
        peer_id: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        is_quic: bool,
        endpoint: &libp2p::core::ConnectedPoint,
    ) -> bool {
                        let mut conn_closing = false;
                        // A circuit reservation is bound to the conn it was
                        // negotiated over — QUIC-pinning a relay's ws/tcp
                        // conn mid-RESERVE kills the pending reservation
                        // (observed: reservation listener dies with the
                        // conn). Relay peers are exempt from pinning, and so
                        // is every conn on a node that relays for others:
                        // the peer's reservation may ride any conn here.
                        let is_known_relay_conn =
                            self.known_relays.iter().any(|(p, _)| *p == peer_id);
                        if is_known_relay_conn || self.should_relay() {
                            // keep every conn — reservations ride them
                        } else if is_quic {
                            // A QUIC conn to this peer exists — close its
                            // non-QUIC conns. request-response picks an
                            // arbitrary conn, and on CGNAT a TCP flow can be
                            // dead-but-ESTABLISHED for ~60s until ping catches
                            // it; sends riding that zombie always time out.
                            // QUIC survives NAT rebinds via connection IDs.
                            let dead: Vec<libp2p::swarm::ConnectionId> = self
                                .conn_quic
                                .get(&peer_id)
                                .map(|m| {
                                    m.iter()
                                        .filter(|(_, q)| !**q)
                                        .map(|(id, _)| *id)
                                        .collect()
                                })
                                .unwrap_or_default();
                            // F8: grace before close — an in-flight request
                            // on the superseded conn gets 20s to finish.
                            // Relayed conns join the retire set too — the
                            // circuit is byte-capped and loses to a proven
                            // direct conn; the fire-time revalidation saves
                            // it if QUIC dies inside the window (EL-02).
                            let deadline = tokio::time::Instant::now()
                                + tokio::time::Duration::from_secs(20);
                            for id in dead {
                                log::debug!(
                                    "Scheduling close of non-QUIC conn {:?} to {} — QUIC pinned (grace 20s)",
                                    id, peer_id
                                );
                                self.pending_conn_close.push((deadline, peer_id, id));
                            }
                        } else {
                            let has_quic = self
                                .conn_quic
                                .get(&peer_id)
                                .map(|m| m.values().any(|q| *q))
                                .unwrap_or(false);
                            if has_quic {
                                // QUIC already lives — this new non-QUIC conn
                                // is another zombie candidate request-response
                                // might pick over the resilient path. A
                                // relayed conn may still carry in-flight
                                // traffic — grace close; a fresh direct conn
                                // has none — close now.
                                if endpoint.is_relayed() {
                                    log::debug!(
                                        "Scheduling close of new relayed conn {:?} to {} — QUIC pinned",
                                        connection_id, peer_id
                                    );
                                    self.pending_conn_close.push((
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20),
                                        peer_id,
                                        connection_id,
                                    ));
                                } else {
                                    log::debug!(
                                        "Closing new non-QUIC conn {:?} to {} — QUIC pinned",
                                        connection_id, peer_id
                                    );
                                    let _ = self.swarm.close_connection(connection_id);
                                }
                                conn_closing = true;
                            } else {
                                // EL-03: deterministic symmetric survivor.
                                // The conn dialed by the SMALLER peer id is
                                // preferred on BOTH ends — for the smaller
                                // peer it is its own outgoing (dialer) conn,
                                // for the larger it is the inbound one — so
                                // both nodes retire the same socket instead
                                // of each killing a different one (the old
                                // "keep freshest" rule disagreed under
                                // simultaneous dials and killed BOTH).
                                // Relayed conns never count as preferred —
                                // a circuit is a byte-capped fallback kept
                                // only while it is the sole path.
                                let prefer_dialer = self.peer_id < peer_id;
                                let relayed_ids = self
                                    .relayed_conn_ids
                                    .get(&peer_id)
                                    .cloned()
                                    .unwrap_or_default();
                                let is_relayed_conn =
                                    |id: &libp2p::swarm::ConnectionId| {
                                        relayed_ids.contains(id)
                                    };
                                let prefers = |id: &libp2p::swarm::ConnectionId| {
                                    !is_relayed_conn(id)
                                        && self
                                            .conn_dialer
                                            .get(id)
                                            .copied()
                                            .unwrap_or(false)
                                            == prefer_dialer
                                };
                                let others: Vec<libp2p::swarm::ConnectionId> = self
                                    .conn_quic
                                    .get(&peer_id)
                                    .map(|m| {
                                        m.keys()
                                            .filter(|id| **id != connection_id)
                                            .copied()
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                if endpoint.is_relayed() {
                                    if others.iter().any(|id| !is_relayed_conn(id)) {
                                        // A direct conn exists — the fresh
                                        // circuit is redundant; retire it
                                        // after grace.
                                        log::debug!(
                                            "Scheduling close of redundant relayed conn {:?} to {} — direct conn exists",
                                            connection_id, peer_id
                                        );
                                        self.pending_conn_close.push((
                                            tokio::time::Instant::now()
                                                + tokio::time::Duration::from_secs(20),
                                            peer_id,
                                            connection_id,
                                        ));
                                        conn_closing = true;
                                    } else {
                                        // Only circuits — keep the freshest,
                                        // retire the siblings.
                                        for id in others {
                                            log::debug!(
                                                "Scheduling close of superseded relayed conn {:?} to {}",
                                                id, peer_id
                                            );
                                            self.pending_conn_close.push((
                                                tokio::time::Instant::now()
                                                    + tokio::time::Duration::from_secs(20),
                                                peer_id,
                                                id,
                                            ));
                                        }
                                    }
                                } else {
                                    let new_preferred = prefers(&connection_id);
                                    let others_preferred =
                                        others.iter().any(prefers);
                                    if new_preferred || !others_preferred {
                                        // This conn survives — retire every
                                        // sibling after grace. With no
                                        // preferred conn at all the freshest
                                        // fallback wins; both ends agree.
                                        let deadline = tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20);
                                        for id in others {
                                            log::debug!(
                                                "Scheduling close of superseded conn {:?} to {} (grace 20s)",
                                                id, peer_id
                                            );
                                            self.pending_conn_close.push((
                                                deadline, peer_id, id,
                                            ));
                                        }
                                    } else {
                                        // A preferred survivor already
                                        // exists — this fresh conn is the
                                        // redundant one; nothing in flight.
                                        log::debug!(
                                            "Closing new non-preferred conn {:?} to {} — symmetric survivor exists",
                                            connection_id, peer_id
                                        );
                                        let _ =
                                            self.swarm.close_connection(connection_id);
                                        conn_closing = true;
                                    }
                                }
                            }
                        }
        conn_closing
    }
}
