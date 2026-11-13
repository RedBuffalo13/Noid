//! Periodic timer arms of the select loop — status-tick bookkeeping and the
//! direct-network keepalive probe. Extracted from the event_loop megaloop
//! (Q04/A5); bodies moved verbatim.

use super::*;

impl P2PNode {
    pub(crate) async fn on_status_tick(&mut self, event_tx: &mpsc::Sender<P2PEvent>) {
                    // RV: expire stale evidence rows; after 60s of probes
                    // with no verdict, `Unknown` becomes an honest
                    // unreachable state instead of endless "Detecting…".
                    self.addr_evidence.sweep_expired();
                    if self.nat_status == NatStatus::Unknown
                        && !self.nat_probe_exhausted
                        && self
                            .nat_probe_opened_at
                            .map(|t| t.elapsed() > std::time::Duration::from_secs(60))
                            .unwrap_or(false)
                    {
                        self.nat_probe_exhausted = true;
                        log::info!("NAT probe window exhausted — status stays unknown; UI reports unreachable");
                        let _ = emit_ev(event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    // RV-06: schedule self-dial probes for unverified addrs.
                    self.maybe_spawn_reach_probe();
                    // META-04: cheap day-rollover check — rebuild rotating
                    // room subscriptions when the epoch day flips.
                    self.refresh_rotating_topics();
                    // F8: close conns whose grace period expired — but
                    // revalidate first (EL-04): during the 20s window the
                    // surviving sibling conn may have died, making the
                    // scheduled conn the LAST path to its peer. Closing it
                    // anyway strands the peer until redial.
                    let now = tokio::time::Instant::now();
                    let (due, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_conn_close)
                        .into_iter()
                        .partition(|(deadline, _, _)| *deadline <= now);
                    self.pending_conn_close = pending;
                    for (_, peer, id) in due {
                        let live = self
                            .conn_quic
                            .get(&peer)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        // Known relays are exempt from the last-conn
                        // protection: a leftover RELAYED conn to a relay
                        // actively harms it (reservation renewals dedup
                        // onto the circuit → nested). Killing it forces
                        // the clean direct redial the relay needs.
                        // The exemption is scoped to relays WE RESERVE ON —
                        // a contact mis-registered as a relay candidate
                        // (HOP protocol + private addr) must keep the
                        // last-conn protection so a scheduled close can
                        // never strand it (TR-01).
                        let is_reserved_relay = self.reserved_relays.contains(&peer);
                        if live <= 1 && !is_reserved_relay {
                            log::debug!(
                                "Canceling scheduled close of {:?} to {} — last live conn",
                                id, peer
                            );
                            continue;
                        }
                        let _ = self.swarm.close_connection(id);
                    }
                    // On-demand teardown: contact conns idle past the TTL
                    // get dropped — the next exchange re-dials on demand.
                    // Infra peers (reserved relays, seeds, mailbox partner)
                    // are exempt — the reservation IS our inbound address.
                    if self.connectivity_config.on_demand {
                        let ttl = std::time::Duration::from_secs(
                            self.connectivity_config.idle_conn_ttl_secs,
                        );
                        let now = tokio::time::Instant::now();
                        let victims: Vec<PeerId> = self
                            .connected_peers
                            .iter()
                            .copied()
                            .filter(|p| {
                                self.conn_class(p)
                                    == crate::p2p::connectivity_config::ConnClass::Contact
                                    && self
                                        .contact_idle_since
                                        .get(p)
                                        .map(|t| now.duration_since(*t) > ttl)
                                        .unwrap_or(true)
                            })
                            .collect();
                        for peer in victims {
                            log::debug!(
                                "On-demand teardown: closing idle contact conn to {}",
                                peer
                            );
                            self.contact_idle_since.remove(&peer);
                            let _ = self.swarm.disconnect_peer_id(peer);
                        }
                        // Drop stale bookkeeping for gone peers.
                        self.contact_idle_since
                            .retain(|p, _| self.connected_peers.contains(p));
                    }

                    // EL-09: pending_app_acks was swept only on insert —
                    // a quiet session let stale channels pile up past the
                    // sender's timeout forever. Sweep on the status tick too.
                    {
                        let cutoff = std::time::Instant::now()
                            - std::time::Duration::from_secs(30);
                        self.pending_app_acks
                            .retain(|_, (_, parked_at)| *parked_at > cutoff);
                    }
                    // DHT-02: flush records whose put_record was refused
                    // synchronously at cold start (empty routing table).
                    self.drain_deferred_dht_puts();
                    let _ = emit_ev(event_tx, P2PEvent::RelayStatusChanged {
                        status: self.relay_status(),
                    }).await;
    }

    pub(crate) async fn on_stun_tick(
        &mut self,
        last_natpmp_probe: &mut std::time::Instant,
        rv_tx: &mpsc::Sender<Vec<std::net::SocketAddr>>,
    ) {
                    // SEC-1111-03: the whole direct-network block (STUN
                    // keepalive, NAT-PMP probe, Mainline-DHT rendezvous
                    // poll) is OFF in RelayedOnly, with an active proxy and
                    // in tor_only — all of them leak our real IP and every
                    // UDP path bypasses the proxy.
                    if !self.direct_net_allowed() {
                        return;
                    }
                    // PersistentKeepalive: refresh the observed STUN mapping
                    // and re-register the external addr if it moved (carrier
                    // NAT re-allocation). Candidates only — AutoNAT remains
                    // the arbiter of confirmed Public reachability.
                    if let Some(mapping) = crate::p2p::stun_keepalive::tick_stun_keepalive(
                        self.relay_config.listen_port,
                    ) {
                        let addr =
                            crate::p2p::stun_keepalive::mapping_to_quic_multiaddr(&mapping);
                        if !self.external_addrs.contains(&addr)
                            && self.relay_config.privacy
                                == crate::p2p::relay_config::PrivacyMode::Direct
                        {
                            log::info!("STUN external addr refreshed: {}", addr);
                            self.swarm.add_external_address(addr.clone());
                            self.external_addrs.push(addr);
                        }
                    }
                    // NAT-PMP lease renewal (~20 min inside the 20s tick).
                    if last_natpmp_probe.elapsed() > std::time::Duration::from_secs(1200) {
                        *last_natpmp_probe = std::time::Instant::now();
                        let p = libp2p_quic::stun_hook::observed_stun_mapping()
                            .map(|m| m.local_port)
                            .unwrap_or(self.relay_config.listen_port);
                        if p != 0 {
                            let lease = tokio::task::spawn_blocking(move || {
                                crate::p2p::nat_pmp::probe_lan_nat_pmp(p, p)
                            })
                            .await
                            .ok()
                            .flatten();
                            if let Some(lease) = lease {
                                for addr in lease.to_multiaddrs() {
                                    if !self.external_addrs.contains(&addr) {
                                        log::info!("NAT-PMP lease renewed → {}", addr);
                                        self.swarm.add_external_address(addr.clone());
                                        self.external_addrs.push(addr);
                                    }
                                }
                                // Only a same-IP STUN match proves the lease
                                // reaches the WAN (no double NAT above the
                                // router).
                                if self.nat_status != NatStatus::Public
                                    && crate::p2p::nat_pmp::lease_confirms_public(&lease)
                                {
                                    self.nat_status = NatStatus::Public;
                                    self.swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .set_mode(Some(kad::Mode::Server));
                                }
                            }
                        }
                    }
                    // Poll OUR rendezvous slots — peers announce their
                    // external addr there; punching back completes the
                    // mutual CGNAT pinhole.
                    {
                        // SEC-1111-03: poll slots named by one-time invite
                        // secrets (TTL'd ring), never by our public PeerId.
                        // Plus our persistent daily rv-v2 slot — contacts
                        // holding our exchanged public key re-find us after
                        // restarts without a fresh invite.
                        const RV_TTL: std::time::Duration =
                            std::time::Duration::from_secs(1800);
                        self.rv_secrets.retain(|(_, ts)| ts.elapsed() < RV_TTL);
                        let mut slots: Vec<String> = self
                            .rv_secrets
                            .iter()
                            .map(|(s, _)| s.clone())
                            .collect();
                        slots.push(
                            crate::p2p::cgnat_rendezvous::own_daily_slot_label(
                                &self.dht_cipher.get_public_key_bytes(),
                            ),
                        );
                        let my_id = self.peer_id.to_string();
                        let tx = rv_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut peers = Vec::new();
                            for slot in slots {
                                for p in crate::p2p::cgnat_rendezvous::announce_and_poll_rendezvous(
                                    &slot, &my_id, 0,
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
}
