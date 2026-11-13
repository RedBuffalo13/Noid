//! P4: signed endpoint records — a peer's own advertisement of how to
//! reach it, signed with its libp2p identity and exchanged only inside
//! authenticated Noise sessions.
//!
//! Bounds (all enforced on ingest, before verification): ≤8 endpoints,
//! ≤4KiB serialized record, ≤24h TTL. A record that fails any check —
//! malformed, forged, stale, expired, oversized — is rejected, never
//! stored. Verified endpoints land in the peer cache (GCM-encrypted at
//! rest) as *hints*: an onion address proves nothing about reachability.

use anyhow::{anyhow, Result};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

use crate::p2p::addr_class::AddrClass;
use crate::p2p::classify_peer_addr::classify_peer_addr;
use crate::security::identity_sig;

/// Max record age accepted on ingest (signed TTL cannot exceed it).
pub const ENDPOINT_TTL_SECS: i64 = 86_400; // 24h
/// Max endpoints per record.
pub const MAX_ENDPOINTS: usize = 8;
/// Max serialized record size (defence against memory/CPU DoS).
pub const MAX_RECORD_BYTES: usize = 4 * 1024;
/// Clock skew tolerated on `issued_at` (records "from the future" beyond
/// this are rejected — replay/DoS control).
const MAX_FUTURE_SKEW_SECS: i64 = 300;

const DOMAIN: &[u8] = b"noid-endpoints-v1";
/// RV-07: separate domain for the optional reachability attestation —
/// independent signature, so v1 records verify unchanged.
const ATTEST_DOMAIN: &[u8] = b"noid-endpoints-attest-v1";

/// RV-07: signed statement "I (record.peer_id) reached `attested_peer`
/// via `reached_via`". Bound to the attested peer — it cannot be replayed
/// as a statement about anyone else. Additive and optional: v1 parsers
/// ignore the field; v1 signature never covers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// PeerId string of the node whose addr is attested.
    pub attested_peer: String,
    /// Canonical multiaddr of the attested peer that worked.
    pub reached_via: String,
    /// Hex ed25519 signature over the attestation payload.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub peer_id: String,
    /// Multiaddr strings — onion3, direct or circuit.
    pub endpoints: Vec<String>,
    pub issued_at: i64,
    /// Embedded expiry — must not exceed issued_at + ENDPOINT_TTL_SECS.
    pub expires_at: i64,
    /// Hex ed25519 signature over the canonical payload.
    pub signature: String,
    /// RV-07: optional mutual-attestation — "the path I used to reach you".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest: Option<Attestation>,
}

/// Canonical signing payload: domain-sep || peer_id || expires_at (BE) ||
/// sorted-unique endpoint strings. Deterministic — the signer and the
/// verifier compute it identically.
fn canonical_payload(record: &EndpointRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(record.peer_id.as_bytes());
    out.extend_from_slice(&record.expires_at.to_be_bytes());
    let mut eps: Vec<&str> = record.endpoints.iter().map(|e| e.as_str()).collect();
    eps.sort_unstable();
    eps.dedup();
    for e in eps {
        out.extend_from_slice(&(e.len() as u16).to_be_bytes());
        out.extend_from_slice(e.as_bytes());
    }
    out
}

/// Sign a fresh record for our own peer — called on the sender side.
pub fn sign_record(
    keypair: &libp2p::identity::Keypair,
    endpoints: Vec<String>,
) -> Result<EndpointRecord> {
    let now = chrono::Utc::now().timestamp();
    let mut record = EndpointRecord {
        peer_id: keypair.public().to_peer_id().to_string(),
        endpoints: endpoints.into_iter().take(MAX_ENDPOINTS).collect(),
        issued_at: now,
        expires_at: now + ENDPOINT_TTL_SECS,
        signature: String::new(),
        attest: None,
    };
    let sig = identity_sig::sign_payload(keypair, &canonical_payload(&record))?;
    record.signature = hex::encode(sig);
    Ok(record)
}

/// Canonical attestation payload: domain || attested_peer || reached_via.
fn attest_payload(attested_peer: &str, reached_via: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(ATTEST_DOMAIN);
    out.extend_from_slice(attested_peer.as_bytes());
    out.extend_from_slice(&(reached_via.len() as u16).to_be_bytes());
    out.extend_from_slice(reached_via.as_bytes());
    out
}

/// RV-07: sign "we reached `attested_peer` via `reached_via`" — attached
/// to the record we send that peer so it learns which of ITS addrs works.
pub fn sign_attestation(
    keypair: &libp2p::identity::Keypair,
    attested_peer: &str,
    reached_via: &str,
) -> Result<Attestation> {
    let sig = identity_sig::sign_payload(keypair, &attest_payload(attested_peer, reached_via))?;
    Ok(Attestation {
        attested_peer: attested_peer.to_string(),
        reached_via: reached_via.to_string(),
        signature: hex::encode(sig),
    })
}

/// Result of verifying an incoming record: usable endpoint hints plus the
/// peer's attestation of OUR addr, when present and correctly signed.
#[derive(Debug)]
pub struct VerifiedEndpoints {
    pub addrs: Vec<Multiaddr>,
    /// The `reached_via` addr the sender attested for US — `Some` only
    /// when the attestation targets us and verifies.
    pub attested_addr: Option<Multiaddr>,
}

/// Verify + canonicalize a received record. Returns classified endpoint
/// hints (only reachable classes kept — Onion3 / PublicDirect / Circuit;
/// LAN addrs are dropped rather than trusted) plus the verified
/// attestation of our own addr when present. `our_peer` binds the
/// attestation: a record carrying an attest for a different peer just
/// yields `attested_addr: None`. Errors on any bounds/schema/expiry/
/// signature failure of the RECORD itself — a malformed attest degrades
/// to `None` instead of rejecting good endpoints.
pub fn verify_and_canonicalize(
    record: &EndpointRecord,
    our_peer: &libp2p::PeerId,
) -> Result<VerifiedEndpoints> {
    if record.peer_id.len() > 64 {
        return Err(anyhow!("peer_id too long"));
    }
    if record.endpoints.len() > MAX_ENDPOINTS {
        return Err(anyhow!("too many endpoints"));
    }
    let serialized = serde_json::to_vec(record)?.len();
    if serialized > MAX_RECORD_BYTES {
        return Err(anyhow!("record too large"));
    }
    let now = chrono::Utc::now().timestamp();
    if record.expires_at <= now {
        return Err(anyhow!("record expired"));
    }
    if record.expires_at - record.issued_at > ENDPOINT_TTL_SECS {
        return Err(anyhow!("record TTL exceeds bound"));
    }
    if record.issued_at > now + MAX_FUTURE_SKEW_SECS {
        return Err(anyhow!("record issued in the future"));
    }
    let peer: libp2p::PeerId = record
        .peer_id
        .parse()
        .map_err(|_| anyhow!("invalid peer id"))?;
    let sig = hex::decode(&record.signature).map_err(|_| anyhow!("bad signature hex"))?;
    if !identity_sig::verify_payload(&record.peer_id, &canonical_payload(record), &sig) {
        return Err(anyhow!("endpoint record signature invalid"));
    }
    let mut out = Vec::new();
    for s in &record.endpoints {
        let Ok(addr) = s.parse::<Multiaddr>() else { continue };
        match classify_peer_addr(&addr, &peer) {
            AddrClass::Onion3 | AddrClass::PublicDirect | AddrClass::Circuit => {
                out.push(addr)
            }
            _ => {} // LAN/Local/Malformed hints are dropped — never stored
        }
    }
    // RV-07: attestation — must name US and carry a valid signature by the
    // record's peer. A bad attest never fails the record.
    let attested_addr = record
        .attest
        .as_ref()
        .filter(|a| a.attested_peer == our_peer.to_string())
        .and_then(|a| {
            let sig = hex::decode(&a.signature).ok()?;
            identity_sig::verify_payload(
                &record.peer_id,
                &attest_payload(&a.attested_peer, &a.reached_via),
                &sig,
            )
            .then(|| a.reached_via.parse::<Multiaddr>().ok())
            .flatten()
        });
    Ok(VerifiedEndpoints { addrs: out, attested_addr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let rec = sign_record(&key, vec![
            "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:4020".into(),
        ])
        .unwrap();
        let ve = verify_and_canonicalize(&rec, &libp2p::PeerId::random()).unwrap();
        assert_eq!(ve.addrs.len(), 1);
        assert!(ve.attested_addr.is_none());
    }

    #[test]
    fn forged_signature_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let other = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.signature = hex::encode(other.sign(b"garbage").unwrap());
        assert!(verify_and_canonicalize(&rec, &libp2p::PeerId::random()).is_err());
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.endpoints.push("/ip4/9.9.9.9/tcp/4001".into());
        assert!(verify_and_canonicalize(&rec, &libp2p::PeerId::random()).is_err());
    }

    #[test]
    fn expired_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec![]).unwrap();
        rec.expires_at = chrono::Utc::now().timestamp() - 1;
        assert!(verify_and_canonicalize(&rec, &libp2p::PeerId::random()).is_err());
    }

    #[test]
    fn bound_enforced() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec![]).unwrap();
        rec.endpoints = (0..9).map(|i| format!("/ip4/10.0.0.{}/tcp/1", i)).collect();
        assert!(verify_and_canonicalize(&rec, &libp2p::PeerId::random()).is_err());
    }

    #[test]
    fn v2_attest_roundtrip() {
        let alice = libp2p::identity::Keypair::generate_ed25519();
        let bob = libp2p::identity::Keypair::generate_ed25519();
        let bob_id = bob.public().to_peer_id();
        let mut rec = sign_record(&alice, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.attest = Some(
            sign_attestation(&alice, &bob_id.to_string(), "/ip4/9.9.9.9/tcp/4020").unwrap(),
        );
        // Bob sees the attestation for him; a third party sees none.
        let ve = verify_and_canonicalize(&rec, &bob_id).unwrap();
        assert_eq!(
            ve.attested_addr.unwrap().to_string(),
            "/ip4/9.9.9.9/tcp/4020"
        );
        let other = verify_and_canonicalize(&rec, &libp2p::PeerId::random()).unwrap();
        assert!(other.attested_addr.is_none());
    }

    #[test]
    fn v2_attest_tamper_ignored() {
        let alice = libp2p::identity::Keypair::generate_ed25519();
        let bob = libp2p::identity::Keypair::generate_ed25519();
        let bob_id = bob.public().to_peer_id();
        let mut rec = sign_record(&alice, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.attest = Some(
            sign_attestation(&alice, &bob_id.to_string(), "/ip4/9.9.9.9/tcp/4020").unwrap(),
        );
        // Forged: attacker claims Alice attested a different addr — sig
        // no longer matches → dropped, endpoints still verify.
        rec.attest.as_mut().unwrap().reached_via = "/ip4/6.6.6.6/tcp/6666".into();
        let ve = verify_and_canonicalize(&rec, &bob_id).unwrap();
        assert!(ve.attested_addr.is_none());
        assert_eq!(ve.addrs.len(), 1);
    }
}
