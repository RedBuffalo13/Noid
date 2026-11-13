//! Verified-reachability evidence ledger for OUR OWN advertised addrs.
//!
//! The phantom-connect problem: an advertised addr (invite hint, endpoint
//! record, STUN mapping) is a *claim*, not proof. This ledger records which
//! local addrs carry positive dial-back / inbound / self-dial evidence.
//! It only ORDERS dial candidates (invite weighting, UI display) — it never
//! blocks a dial and never writes to `dead_addrs`; an unverified addr is
//! always a valid fallback.
//!
//! In-memory only — nothing persists, so KillPin/wipe is unaffected and no
//! new secrets exist. Sources with different confidence feed the same map;
//! `Candidate` is "observed but unproven" (STUN mapping), `Verified` is
//! "a real peer or probe reached us here", `Failed` is "a proof attempt
//! specifically failed" (not merely absent — absence stays `None`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long positive evidence remains trusted — network/NAT mappings can
/// flap, so verification decays and must be re-earned.
const VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);
/// Failure marks decay faster — a Failed addr may recover on a network
/// change and should get re-probed rather than stay blacklisted.
const FAILED_TTL: Duration = Duration::from_secs(10 * 60);

/// What proved (or disproved) reachability of one of our addrs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    /// AutoNAT dial-back probe: a connected peer dialed this addr and the
    /// response confirmed receipt (or `ExternalAddrConfirmed` fired).
    AutonatProbe,
    /// An inbound connection landed on this local listen endpoint —
    /// a real peer reached us through it.
    InboundConn,
    /// Our own self-dial probe swarm reached us through this addr.
    SelfDial,
    /// UPnP gateway confirmed the external mapping (NewExternalAddr).
    UpnpLease,
    /// NAT-PMP lease whose external IP matches STUN observation.
    NatPmp,
    /// STUN observed an external mapping — a candidate only; the mapping
    /// does not prove inbound filtering lets packets through.
    StunMap,
    /// A peer's signed EndpointAdvertise v2 attestation named this addr
    /// as the path it used to reach us.
    PeerAttest,
    /// Tor self-connect probe reached our own onion service end-to-end
    /// (descriptor fetch + intro + rendezvous + accept loop).
    OnionSelfProbe,
}

/// Confidence tier of the latest evidence for an addr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    /// Positive proof exists within TTL — a peer or probe reached us.
    Verified,
    /// Observed hint without a reachability proof (STUN mapping etc.).
    Candidate,
    /// A concrete proof attempt failed (probe error, self-dial timeout).
    Failed,
}

/// One ledger row: latest state, its source and when it was recorded.
#[derive(Debug, Clone)]
pub struct AddrEvidence {
    pub state: EvidenceState,
    pub source: EvidenceSource,
    at: Instant,
}

impl AddrEvidence {
    fn is_fresh(&self) -> bool {
        let ttl = match self.state {
            EvidenceState::Verified => VERIFIED_TTL,
            EvidenceState::Failed => FAILED_TTL,
            // Candidates never expire on their own — they are superseded by
            // real evidence or dropped when the addr itself disappears.
            EvidenceState::Candidate => return true,
        };
        self.at.elapsed() < ttl
    }
}

/// Canonical addr string → latest evidence. Empty map = nothing proven yet
/// (cold start is the normal state, not an error).
#[derive(Debug, Default)]
pub struct EvidenceLedger {
    map: HashMap<String, AddrEvidence>,
}

impl EvidenceLedger {
    /// Record evidence for `canonical_addr` (already normalized via
    /// `P2PNode::canonical_dial_addr` by the caller). Verified/Fail entries
    /// always overwrite; a new Candidate never downgrades live Verified
    /// evidence (a STUN refresh must not erase a proven addr).
    pub fn mark(&mut self, canonical_addr: &str, state: EvidenceState, source: EvidenceSource) {
        if state == EvidenceState::Candidate {
            if let Some(prev) = self.map.get(canonical_addr) {
                if prev.state == EvidenceState::Verified && prev.is_fresh() {
                    return;
                }
            }
        }
        self.map.insert(
            canonical_addr.to_string(),
            AddrEvidence { state, source, at: Instant::now() },
        );
    }

    /// Mark `Failed` only when no live Verified evidence stands — a fresh
    /// probe failure must not erase a recently proven path (the earlier
    /// success may reflect a network state we still sit in).
    pub fn mark_failed_if_unverified(&mut self, canonical_addr: &str, source: EvidenceSource) {
        if !self.is_verified(canonical_addr) {
            self.mark(canonical_addr, EvidenceState::Failed, source);
        }
    }

    /// Latest fresh state for an addr, `None` when unknown or expired.
    pub fn state_of(&self, canonical_addr: &str) -> Option<EvidenceState> {
        self.map
            .get(canonical_addr)
            .filter(|e| e.is_fresh())
            .map(|e| e.state)
    }

    /// True when live Verified evidence exists for the addr.
    pub fn is_verified(&self, canonical_addr: &str) -> bool {
        self.state_of(canonical_addr) == Some(EvidenceState::Verified)
    }

    /// Drop expired Verified/Failed rows (Candidate rows persist with their
    /// addr). Called on the maintenance tick — bounded map stays bounded.
    pub fn sweep_expired(&mut self) {
        self.map.retain(|_, e| e.is_fresh());
    }

    /// Diagnostic count for logging/status.
    pub fn verified_count(&self) -> usize {
        self.map
            .values()
            .filter(|e| e.state == EvidenceState::Verified && e.is_fresh())
            .count()
    }

    /// Fresh state snapshot for `RelayStatus` — the invite builder ranks
    /// candidates off this without holding the live ledger.
    pub fn snapshot(&self) -> HashMap<String, EvidenceState> {
        self.map
            .iter()
            .filter(|(_, e)| e.is_fresh())
            .map(|(k, e)| (k.clone(), e.state))
            .collect()
    }
}

impl crate::p2p::node::P2PNode {
    /// RV-02: an inbound conn just landed on `local_addr` — a real peer
    /// reached us through whatever we advertised that maps to it. Mark the
    /// matching advertised addr Verified (inbound proof beats any probe).
    ///
    /// Matching is deliberately shape-based: the listener reports a
    /// wildcard IP (`0.0.0.0`) or a circuit form that only prefixes the
    /// stored endpoint, so equality rarely applies. Rules:
    /// - circuit inbound → the relayed addr sharing the circuit prefix;
    /// - onion inbound → our single onion listen addr;
    /// - direct inbound → external addrs sharing the transport tail
    ///   (`tcp|udp/<port>[/quic-v1][/ws]`).
    pub(crate) fn note_inbound_path(&mut self, local_addr: &libp2p::Multiaddr) {
        use libp2p::multiaddr::Protocol;
        let is_circuit = local_addr
            .iter()
            .any(|p| matches!(p, Protocol::P2pCircuit));
        let is_onion = local_addr
            .iter()
            .any(|p| matches!(p, Protocol::Onion3(_)));
        let tail = transport_tail(local_addr);

        let mut candidates: Vec<libp2p::Multiaddr> = Vec::new();
        candidates.extend(self.external_addrs.iter().cloned());
        candidates.extend(self.relayed_addrs.iter().cloned());
        if let Some(o) = &self.own_onion_addr {
            candidates.push(o.clone());
        }
        for cand in candidates {
            let c_circuit = cand
                .iter()
                .any(|p| matches!(p, Protocol::P2pCircuit));
            let c_onion = cand
                .iter()
                .any(|p| matches!(p, Protocol::Onion3(_)));
            let matched = if is_circuit && c_circuit {
                addr_prefix(local_addr, &cand)
            } else if is_onion && c_onion {
                true
            } else if !is_circuit && !is_onion && !c_circuit && !c_onion {
                !tail.is_empty() && transport_tail(&cand) == tail
            } else {
                false
            };
            if matched {
                let key = Self::canonical_dial_addr(&cand).to_string();
                if !self.addr_evidence.is_verified(&key) {
                    self.addr_evidence.mark(
                        &key,
                        EvidenceState::Verified,
                        EvidenceSource::InboundConn,
                    );
                    log::info!("Inbound conn verified our advertised addr {}", key);
                }
            }
        }
    }
}

/// Non-IP protocol tail — e.g. `["udp/4020","quic-v1"]` — used to bind a
/// wildcard listener addr to its advertised external form.
fn transport_tail(addr: &libp2p::Multiaddr) -> Vec<String> {
    use libp2p::multiaddr::Protocol;
    addr.iter()
        .filter_map(|p| match p {
            Protocol::Tcp(p) => Some(format!("tcp/{p}")),
            Protocol::Udp(p) => Some(format!("udp/{p}")),
            Protocol::QuicV1 => Some("quic-v1".into()),
            Protocol::Ws(_) => Some("ws".into()),
            _ => None,
        })
        .collect()
}

/// True when `a`'s protocol sequence is a prefix of `b`'s.
fn addr_prefix(a: &libp2p::Multiaddr, b: &libp2p::Multiaddr) -> bool {
    let av: Vec<_> = a.iter().collect();
    let bv: Vec<_> = b.iter().collect();
    av.len() <= bv.len() && av.iter().zip(bv.iter()).all(|(x, y)| x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_query_verified() {
        let mut l = EvidenceLedger::default();
        assert_eq!(l.state_of("/ip4/1.2.3.4/udp/4020/quic-v1"), None);
        l.mark(
            "/ip4/1.2.3.4/udp/4020/quic-v1",
            EvidenceState::Verified,
            EvidenceSource::AutonatProbe,
        );
        assert!(l.is_verified("/ip4/1.2.3.4/udp/4020/quic-v1"));
        assert_eq!(l.verified_count(), 1);
    }

    #[test]
    fn candidate_does_not_downgrade_verified() {
        let mut l = EvidenceLedger::default();
        let a = "/ip4/1.2.3.4/tcp/4020";
        l.mark(a, EvidenceState::Verified, EvidenceSource::InboundConn);
        l.mark(a, EvidenceState::Candidate, EvidenceSource::StunMap);
        assert_eq!(l.state_of(a), Some(EvidenceState::Verified));
    }

    #[test]
    fn failed_overrides_verified() {
        let mut l = EvidenceLedger::default();
        let a = "/ip4/9.9.9.9/tcp/4020";
        l.mark(a, EvidenceState::Verified, EvidenceSource::AutonatProbe);
        l.mark(a, EvidenceState::Failed, EvidenceSource::SelfDial);
        assert_eq!(l.state_of(a), Some(EvidenceState::Failed));
    }

    #[test]
    fn expired_verified_returns_none() {
        let mut l = EvidenceLedger::default();
        let a = "/ip4/5.6.7.8/tcp/4020";
        l.map.insert(
            a.to_string(),
            AddrEvidence {
                state: EvidenceState::Verified,
                source: EvidenceSource::UpnpLease,
                at: Instant::now() - VERIFIED_TTL - Duration::from_secs(1),
            },
        );
        assert_eq!(l.state_of(a), None);
        l.sweep_expired();
        assert!(l.map.is_empty());
    }

    #[test]
    fn multiaddr_roundtrip_key() {
        let m: libp2p::Multiaddr = "/ip4/1.2.3.4/udp/4020/quic-v1".parse().unwrap();
        let mut l = EvidenceLedger::default();
        l.mark(&m.to_string(), EvidenceState::Candidate, EvidenceSource::StunMap);
        assert_eq!(l.state_of(&m.to_string()), Some(EvidenceState::Candidate));
    }
}
