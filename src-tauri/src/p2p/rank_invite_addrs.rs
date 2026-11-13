//! RV-04: order invite addr hints by verified reachability.
//!
//! An invite is a dial plan for a cold peer — hints should put proven
//! paths first. Ranking only reorders; no addr is dropped (the caller's
//! `MAX_BUILD_ADDRS` cap still applies, so verified candidates win the
//! limited slots and unverified ones remain fallback hints inside the
//! cap rather than disappearing from the system).
//!
//! Order: onion3 → verified direct → unverified direct → verified
//! circuit → circuit → observed candidates (STUN) → failed → rest.

use std::collections::HashMap;

use libp2p::{Multiaddr, PeerId};

use crate::p2p::addr_class::AddrClass;
use crate::p2p::addr_evidence::EvidenceState;
use crate::p2p::classify_peer_addr::classify_peer_addr;
use crate::p2p::node::P2PNode;

fn rank_key(
    addr: &Multiaddr,
    peer: &PeerId,
    evidence: &HashMap<String, EvidenceState>,
) -> u8 {
    let class = classify_peer_addr(addr, peer);
    let canonical = P2PNode::canonical_dial_addr(addr).to_string();
    let state = evidence.get(&canonical).copied();
    match (class, state) {
        (AddrClass::Onion3, _) => 0,
        (AddrClass::PublicDirect | AddrClass::Lan, Some(EvidenceState::Verified)) => 10,
        (AddrClass::PublicDirect | AddrClass::Lan, Some(EvidenceState::Failed)) => 60,
        (AddrClass::PublicDirect | AddrClass::Lan, Some(EvidenceState::Candidate)) => 50,
        (AddrClass::PublicDirect | AddrClass::Lan, None) => 20,
        (AddrClass::Circuit, Some(EvidenceState::Verified)) => 30,
        (AddrClass::Circuit, Some(EvidenceState::Failed)) => 60,
        (AddrClass::Circuit, _) => 40,
        (_, Some(EvidenceState::Failed)) => 60,
        _ => 70,
    }
}

/// Stable-sort invite hint addrs best-first. `evidence` is a fresh
/// `EvidenceLedger::snapshot()` keyed by canonical addr string. `peer` is
/// OUR peer id — the classifier needs the terminal `/p2p` id to call a
/// circuit a circuit (a bare relay addr is a relay, not our endpoint).
pub fn rank_invite_addrs(
    addrs: Vec<String>,
    peer: &PeerId,
    evidence: &HashMap<String, EvidenceState>,
) -> Vec<String> {
    let mut keyed: Vec<(u8, String)> = addrs
        .into_iter()
        .map(|s| {
            let key = s
                .parse::<Multiaddr>()
                .map(|m| rank_key(&m, peer, evidence))
                .unwrap_or(80);
            (key, s)
        })
        .collect();
    keyed.sort_by_key(|(k, _)| *k);
    keyed.into_iter().map(|(_, s)| s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn ev(pairs: &[(&str, EvidenceState)]) -> HashMap<String, EvidenceState> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn verified_direct_beats_unverified_and_circuit() {
        let p = pid();
        let direct = format!("/ip4/203.0.113.7/udp/4020/quic-v1/p2p/{}", p);
        let circuit = format!(
            "/ip4/198.51.100.1/udp/4020/quic-v1/p2p/12D3KooWHRrrzP1nMJzJV2VU3vkiBGbJ8iGUPRJKhBxeEK9ysW7R/p2p-circuit/p2p/{}",
            p
        );
        let onion = format!("/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:4020/p2p/{}", p);
        let ledger = ev(&[("/ip4/203.0.113.7/udp/4020/quic-v1", EvidenceState::Verified)]);
        let ranked = rank_invite_addrs(
            vec![circuit.clone(), direct.clone(), onion.clone()],
            &p,
            &ledger,
        );
        assert_eq!(ranked, vec![onion, direct, circuit]);
    }

    #[test]
    fn unverified_direct_still_beats_stun_candidate() {
        let p = pid();
        let stun = format!("/ip4/203.0.113.9/udp/4020/quic-v1/p2p/{}", p);
        let plain = format!("/ip4/198.51.100.9/tcp/4020/p2p/{}", p);
        let ledger = ev(&[("/ip4/203.0.113.9/udp/4020/quic-v1", EvidenceState::Candidate)]);
        let ranked = rank_invite_addrs(vec![stun.clone(), plain.clone()], &p, &ledger);
        assert_eq!(ranked, vec![plain, stun]);
    }

    #[test]
    fn failed_direct_falls_to_bottom() {
        let p = pid();
        let bad = format!("/ip4/203.0.113.9/tcp/4020/p2p/{}", p);
        let ok = format!("/ip4/198.51.100.9/tcp/4020/p2p/{}", p);
        let ledger = ev(&[("/ip4/203.0.113.9/tcp/4020", EvidenceState::Failed)]);
        let ranked = rank_invite_addrs(vec![bad.clone(), ok.clone()], &p, &ledger);
        assert_eq!(ranked, vec![ok, bad]);
    }

    #[test]
    fn nothing_is_dropped() {
        let p = pid();
        let addrs = vec![
            format!("/ip4/203.0.113.7/tcp/4020/p2p/{}", p),
            "not-an-addr".to_string(),
        ];
        let ledger = HashMap::new();
        assert_eq!(rank_invite_addrs(addrs, &p, &ledger).len(), 2);
    }
}
