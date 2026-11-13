use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{autonat, gossipsub, identify, kad, mdns, ping, relay, request_response, upnp, Multiaddr, PeerId};
use tokio::sync::mpsc;

use crate::p2p::behaviour::NoidBehaviourEvent;
use crate::p2p::get_record_miss::TerminalCause;
use crate::p2p::node::P2PNode;
use crate::p2p::relay_status::NatStatus;
use crate::p2p::types::{DHTUserRecord, P2PCommand, P2PEvent};

/// Bounded event send (F5/RC3): `send().await?` on the bounded forwarder
/// channel used to kill the whole event loop when the channel filled or the
/// forwarder died — and a permanently blocked send deadlocked the
/// cmd-channel drain (circular wait). A full channel now waits up to 5s
/// then drops the event (delivery-critical events self-heal via
/// pending/mailbox retry); a closed channel stops the node gracefully.
pub(crate) async fn emit_ev(event_tx: &mpsc::Sender<P2PEvent>, ev: P2PEvent) -> bool {
    match tokio::time::timeout(std::time::Duration::from_secs(5), event_tx.send(ev)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => {
            log::error!("P2P event channel closed — stopping node");
            false
        }
        Err(_) => {
            log::warn!("P2P event channel blocked >5s — dropping event");
            true
        }
    }
}

mod cmd;
mod cmd_tail;
mod conn;
mod conn_err;
mod conn_peer;
mod conn_pin;
mod hop_arm;
mod kad_ev;
mod kad_tail;
mod mailbox_arm;
mod maint;
mod misc;
mod net_aux;
mod proto;
mod room_arm;

/// Shared context passed to extracted arm handlers — the bounded event
/// forwarder and the rendezvous-result channel (command arms only).
pub(crate) struct LoopCtx<'a> {
    pub event_tx: &'a mpsc::Sender<P2PEvent>,
    pub rv_tx: &'a mpsc::Sender<Vec<std::net::SocketAddr>>,
}

/// Arm-handler return: `Keep` = continue the select loop, `Exit` = the arm
/// asked `run()` to terminate (Shutdown, closed event channel).
#[derive(Debug, PartialEq)]
pub(crate) enum LoopCtl {
    Keep,
    Exit,
}
impl P2PNode {
    pub async fn run(
        mut self,
        event_tx: mpsc::Sender<P2PEvent>,
        mut cmd_rx: mpsc::Receiver<P2PCommand>,
    ) -> anyhow::Result<()> {
        // Phase J.1: Periodic cleanup of expired mailbox messages (every hour)
        let mut mailbox_cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        // Relay maintenance: renew reservations (~30min), re-discover relays.
        let mut relay_maintain_interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
        // Peer cache flush must not wait for the 10-min maintenance tick —
        // a short session (connect, chat a minute, quit) would otherwise
        // never persist discovered peers and the next start is cold again.
        let mut peer_cache_flush = tokio::time::interval(tokio::time::Duration::from_secs(30));
        // UI status heartbeat: events-only reporting left the panel frozen on
        // the default snapshot whenever a listener missed the early emits.
        let mut status_tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
        // Pinned seed dials behind a shared port randomly land on the wrong
        // peer — bootstrap() never retries, so do it here until connected.
        let mut bootstrap_retry_interval =
            tokio::time::interval(tokio::time::Duration::from_secs(30));
        // WireGuard-style PersistentKeepalive: a 20s UDP pulse from the QUIC
        // listener socket keeps the router/CGNAT mapping open (mobile CGNATs
        // expire UDP state in 15-45s).
        let mut stun_keepalive_interval =
            tokio::time::interval(crate::p2p::stun_keepalive::STUN_KEEPALIVE_INTERVAL);
        // Rendezvous results arrive from spawn_blocking tasks on this channel
        // (Mainline-DHT announce/poll is synchronous UDP, ~1.5s worst case).
        let (rv_tx, mut rv_rx) = mpsc::channel::<Vec<std::net::SocketAddr>>(8);
        // RV-06: self-dial probe results land here — the loop marks the
        // evidence ledger; failures stay out of `dead_addrs`.
        let (probe_tx, mut probe_rx) =
            mpsc::channel::<crate::p2p::reach_probe::ProbeResult>(8);
        self.probe_tx = Some(probe_tx);
        let mut rv_punched: std::collections::HashMap<
            std::net::SocketAddr,
            std::time::Instant,
        > = std::collections::HashMap::new();
        // NAT-PMP leases live 1h — re-probe inside the 20s tick at ~20min.
        let mut last_natpmp_probe = std::time::Instant::now();
        // B5: fast tick draining a debounced NetworkChanged — one handler
        // run per burst, not one per ConnectivityManager callback.
        let mut netchange_tick = tokio::time::interval(tokio::time::Duration::from_secs(1));
        netchange_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let ctx = LoopCtx {
            event_tx: &event_tx,
            rv_tx: &rv_tx,
        };
        loop {
            tokio::select! {
                _ = netchange_tick.tick() => {
                    if self.pending_network_change {
                        self.pending_network_change = false;
                        self.last_network_change = Some(std::time::Instant::now());
                        self.on_network_changed();
                    }
                    // Deferred rendezvous re-dial: the first dial fired
                    // before the mutual punch opened the CGNAT pinholes;
                    // the second rides the just-opened hole.
                    if !self.deferred_dials.is_empty() {
                        let now = std::time::Instant::now();
                        let (due, keep): (Vec<_>, Vec<_>) =
                            std::mem::take(&mut self.deferred_dials)
                                .into_iter()
                                .partition(|(t, _)| *t <= now);
                        self.deferred_dials = keep;
                        for (_, maddr) in due {
                            let _ = self.dial(maddr).await;
                        }
                    }
                }
                _ = relay_maintain_interval.tick() => {
                    // Renew circuit reservations before they expire (~1h TTL)
                    self.refresh_reservations();
                    // DHT work is pointless with zero connections — every
                    // query only churns the routing table into internal dials
                    // that all fail. Wait for the first connection (bootstrap,
                    // cached relay, or mDNS peer).
                    if self.connected_peers.is_empty() {
                        continue;
                    }
                    // Keep looking for relays until we have a few options.
                    // D5: known_relays holds (peer, addr) pairs — count
                    // distinct peers, not addresses (bundled seeds carry
                    // 5 addrs for 2 peers).
                    {
                        let distinct: std::collections::HashSet<_> =
                            self.known_relays.iter().map(|(p, _)| *p).collect();
                        if distinct.len() < 3 {
                            self.discover_relays();
                        }
                    }
                    // (Re-)announce ourselves as relay provider when reachable
                    if self.should_relay() && !self.relay_provider_announced {
                        self.advertise_as_relay();
                    }
                    // Random Kademlia walk: refreshes the routing table and
                    // pulls in peers from any "circles" that bridged into ours.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .get_closest_peers(libp2p::PeerId::random());
                }
                _ = status_tick.tick() => self.on_status_tick(&event_tx).await,
                _ = bootstrap_retry_interval.tick() => {
                    self.retry_bootstrap_dials();
                }
                _ = stun_keepalive_interval.tick() => self.on_stun_tick(&mut last_natpmp_probe, &rv_tx).await,
                Some(res) = probe_rx.recv() => {
                    self.probe_in_flight = self.probe_in_flight.saturating_sub(1);
                    use crate::p2p::addr_evidence::{EvidenceState, EvidenceSource};
                    if res.ok {
                        self.addr_evidence.mark(
                            &res.canonical,
                            EvidenceState::Verified,
                            EvidenceSource::SelfDial,
                        );
                        log::info!("Reach probe verified {}", res.canonical);
                    } else {
                        self.addr_evidence.mark_failed_if_unverified(
                            &res.canonical,
                            EvidenceSource::SelfDial,
                        );
                        log::info!("Reach probe failed {}", res.canonical);
                    }
                }
                Some(peers) = rv_rx.recv() => {
                    let now = std::time::Instant::now();
                    for sa in peers {
                        // 15s dedup: a single slot poll cycle should not
                        // re-punch, but a missed punch (CGNAT timing) must
                        // be retryable within the rendezvous window —
                        // 300s permanently locked out slow pinholes.
                        let fresh = rv_punched
                            .get(&sa)
                            .map(|t| {
                                now.duration_since(*t) < std::time::Duration::from_secs(15)
                            })
                            .unwrap_or(false);
                        if fresh {
                            continue;
                        }
                        rv_punched.insert(sa, now);
                        crate::p2p::punch_assist::spawn_udp_punch_burst(sa, true);
                        let mut maddr = Multiaddr::empty();
                        match sa.ip() {
                            std::net::IpAddr::V4(v4) => {
                                maddr.push(libp2p::multiaddr::Protocol::Ip4(v4))
                            }
                            std::net::IpAddr::V6(v6) => {
                                maddr.push(libp2p::multiaddr::Protocol::Ip6(v6))
                            }
                        }
                        maddr.push(libp2p::multiaddr::Protocol::Udp(sa.port()));
                        maddr.push(libp2p::multiaddr::Protocol::QuicV1);
                        log::info!(
                            "Rendezvous peer discovered at {} — mutual punch + dial",
                            sa
                        );
                        let _ = self.dial(maddr.clone()).await;
                        // Second dial ~1s later: the first one fires before
                        // our punch packets opened the remote pinhole; the
                        // retry lands inside the just-opened window.
                        self.deferred_dials.push((
                            now + std::time::Duration::from_millis(900),
                            maddr,
                        ));
                    }
                }
                _ = peer_cache_flush.tick() => {
                    if self.peer_cache_dirty {
                        self.peer_cache
                            .save(&self.data_dir.clone(), self.field_cipher.as_deref());
                        self.peer_cache_dirty = false;
                    }
                }
                _ = mailbox_cleanup_interval.tick() => {
                    // Phase J.1: Clean up expired mailbox messages from local storage
                    if let Some(ref db) = self.db {
                        let db_guard = db.lock().await;
                        if let Some(ref db) = *db_guard {
                            match db.cleanup_expired_mailbox().await {
                                Ok(n) => {
                                    if n > 0 {
                                        log::debug!("Cleaned up {} expired mailbox messages", n);
                                    }
                                }
                                Err(e) => log::error!("Mailbox cleanup failed: {}", e),
                            }
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(command) => {
                            if let LoopCtl::Exit = self.on_command(command, &ctx).await {
                                break Ok(());
                            }
                        }
                        None => {
                            // Phase 1.9: cmd channel closed — terminate event loop cleanly
                            // instead of busy-looping forever.
                            log::debug!("P2P command channel closed, shutting down event loop");
                            break Ok(());
                        }
                    }
                }

                event = self.swarm.select_next_some() => {
                    let ctl = match event {
                        SwarmEvent::NewListenAddr { .. }
                        | SwarmEvent::ExpiredListenAddr { .. }
                        | SwarmEvent::ExternalAddrConfirmed { .. }
                        | SwarmEvent::ExternalAddrExpired { .. }
                        | SwarmEvent::ConnectionEstablished { .. }
                        | SwarmEvent::ConnectionClosed { .. }
                        | SwarmEvent::OutgoingConnectionError { .. }
                        | SwarmEvent::IncomingConnectionError { .. }
                        | SwarmEvent::ListenerError { .. }
                        | SwarmEvent::ListenerClosed { .. } => {
                            self.on_conn_event(event, &ctx).await
                        }
                        SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(_)) => {
                            self.on_kad_event(event, &ctx).await
                        }
                        SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Hop(_)) => {
                            self.on_proto_event(event, &ctx).await
                        }
                        SwarmEvent::Behaviour(NoidBehaviourEvent::Mdns(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Identify(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Gossipsub(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Autonat(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Dcutr(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::RelayClient(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(_))
                        | SwarmEvent::Behaviour(NoidBehaviourEvent::Ping(_)) => {
                            self.on_misc_event(event, &ctx).await
                        }
                        other => {
                            log::debug!("Unhandled swarm event: {:?}", other);
                            LoopCtl::Keep
                        }
                    };
                    if let LoopCtl::Exit = ctl {
                        break Ok(());
                    }
                }
            }
        }
    }

    /// Phase J.2: Set the audit log reference for DHT/replay/screenshot logging.
    pub fn set_audit_log(&mut self, log: std::sync::Arc<crate::security::audit_log::AuditLog>) {
        self.audit_log = Some(log);
    }
}
