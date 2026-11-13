//! RV-06: self-dial reachability probes over a throwaway identity.
//!
//! An advertised addr stays a *claim* until something dials it. AutoNAT
//! covers addrs its probes happen to test; this probe closes the rest —
//! circuit addrs AutoNAT never touches and direct addrs it skipped. The
//! probe is a one-shot swarm on a FRESH keypair (same privacy stance as
//! `ephemeral_peer`: the self-probe must not be linkable to our stable
//! transport identity) speaking only `ping` + the relay client — enough
//! to complete a real Noise+Yamux handshake and one ping round-trip.
//!
//! Results go back to the event loop which marks the evidence ledger —
//! `Failed` marks land in the ledger ONLY, never in `dead_addrs`: these
//! are our own addrs, and a probe failure must not poison peer-facing
//! failure bookkeeping.

use anyhow::Result;
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{noise, ping, relay, tcp, yamux, Multiaddr, PeerId, Swarm};
use std::time::Duration;
use tokio::sync::mpsc;

/// Per-addr dial budget — QUIC handshake + ping on a slow path.
const PER_ADDR_TIMEOUT: Duration = Duration::from_secs(15);
/// Whole-batch bound so a dead addr cannot pin the task.
const BATCH_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(NetworkBehaviour)]
struct ProbeBehaviour {
    relay_client: relay::client::Behaviour,
    ping: ping::Behaviour,
}

fn build_probe_swarm() -> Result<Swarm<ProbeBehaviour>> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let builder = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic_config(|mut cfg| {
            cfg.max_idle_timeout = 30_000;
            cfg
        })
        .with_other_transport(crate::p2p::swarm_builder::ws_transport)?;
    #[cfg(not(target_os = "android"))]
    let builder = builder.with_dns()?;
    Ok(builder
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_key, relay_client| ProbeBehaviour {
            relay_client,
            ping: ping::Behaviour::new(ping::Config::new()),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(BATCH_TIMEOUT))
        .build())
}

/// Result of probing one advertised addr end-to-end.
#[derive(Debug)]
pub struct ProbeResult {
    /// Canonical dial addr as passed in.
    pub canonical: String,
    /// True when the probe completed a conn + one ping round-trip.
    pub ok: bool,
}

/// How often the scheduler may launch a probe batch — rate limit per
/// the design (extra self-conns are metadata a relay can observe).
const PROBE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Max addrs probed per batch.
const PROBE_BATCH_MAX: usize = 4;

impl crate::p2p::node::P2PNode {
    /// RV-06 scheduler (status tick): probe still-unproven advertised addrs.
    ///
    /// Guards — probing must never enlarge the privacy surface:
    /// - `TorOnly`/proxy/relayed_only: no direct probing at all (the probe
    ///   swarm has no onion transport; under tor_only every self-dial would
    ///   leak over the clearnet).
    /// - Direct external addrs additionally require `direct_net_allowed()`.
    /// - Circuit addrs probe only while a reservation backs them.
    /// Rate-limited to one batch per `PROBE_INTERVAL`, ≤ `PROBE_BATCH_MAX` addrs,
    /// results counted down in `probe_in_flight`.
    pub(crate) fn maybe_spawn_reach_probe(&mut self) {
        use crate::p2p::addr_evidence::EvidenceState;
        if self.probe_in_flight > 0 {
            // Stale guard: a probe task that died before reporting every
            // addr would wedge the scheduler forever — once the worst-case
            // batch duration has passed the count is declared stale.
            let stale = self
                .probe_last_run
                .map(|t| {
                    t.elapsed()
                        > PER_ADDR_TIMEOUT * PROBE_BATCH_MAX as u32
                            + Duration::from_secs(60)
                })
                .unwrap_or(true);
            if !stale {
                return;
            }
            self.probe_in_flight = 0;
        }
        if self
            .probe_last_run
            .map(|t| t.elapsed() < PROBE_INTERVAL)
            .unwrap_or(false)
        {
            return;
        }
        let Some(tx) = self.probe_tx.clone() else {
            return;
        };
        let tor_only = self
            .tor
            .as_ref()
            .map(|t| t.status().desired_mode == crate::p2p::tor::mode::TorMode::TorOnly)
            .unwrap_or(false);
        if tor_only {
            return;
        }
        let direct_ok = self.direct_net_allowed();
        let target = self.peer_id;
        let mut candidates: Vec<Multiaddr> = Vec::new();
        let consider = |evidence: &crate::p2p::addr_evidence::EvidenceLedger,
                            a: &Multiaddr| {
            let key = crate::p2p::node::P2PNode::canonical_dial_addr(a).to_string();
            match evidence.state_of(&key) {
                None | Some(EvidenceState::Candidate) => {
                    let mut d = a.clone();
                    if !matches!(d.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(_))) {
                        d.push(libp2p::multiaddr::Protocol::P2p(target));
                    }
                    Some(d)
                }
                _ => None,
            }
        };
        if direct_ok {
            for a in &self.external_addrs {
                if let Some(d) = consider(&self.addr_evidence, a) {
                    candidates.push(d);
                }
            }
        }
        if !self.relayed_addrs.is_empty() {
            for a in &self.relayed_addrs {
                if let Some(d) = consider(&self.addr_evidence, a) {
                    candidates.push(d);
                }
            }
        }
        candidates.truncate(PROBE_BATCH_MAX);
        if candidates.is_empty() {
            return;
        }
        self.probe_last_run = Some(std::time::Instant::now());
        self.probe_in_flight = candidates.len() as u8;
        log::info!("Reach probe: dialing {} self-addrs", candidates.len());
        tokio::spawn(async move {
            probe_batch(candidates, target, tx).await;
        });
    }
}

/// Dial each addr in order; report per-addr success through `tx`.
/// `target` is our own peer id — the probe swarm has a fresh identity,
/// so libp2p treats this as an ordinary remote dial.
pub async fn probe_batch(
    addrs: Vec<Multiaddr>,
    target: PeerId,
    tx: mpsc::Sender<ProbeResult>,
) {
    for addr in addrs {
        let canonical = addr.to_string();
        let ok = match probe_one(&addr, target).await {
            Ok(ok) => ok,
            Err(e) => {
                log::debug!("reach probe {} error: {}", canonical, e);
                false
            }
        };
        let _ = tx.send(ProbeResult { canonical, ok }).await;
    }
}

async fn probe_one(addr: &Multiaddr, target: PeerId) -> Result<bool> {
    let mut swarm = build_probe_swarm()?;
    swarm.dial(addr.clone())?;
    let mut established = false;
    let deadline = tokio::time::sleep(PER_ADDR_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Ok(false),
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if peer_id == target {
                        established = true;
                    }
                }
                SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(ping::Event {
                    peer, result: Ok(_), ..
                })) if peer == target && established => {
                    return Ok(true);
                }
                SwarmEvent::OutgoingConnectionError { .. } => return Ok(false),
                _ => {}
            },
        }
    }
}
