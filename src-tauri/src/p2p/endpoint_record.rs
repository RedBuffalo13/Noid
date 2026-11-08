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
    };
    let sig = identity_sig::sign_payload(keypair, &canonical_payload(&record))?;
    record.signature = hex::encode(sig);
    Ok(record)
}

/// Verify + canonicalize a received record. Returns the deduped, classified
/// endpoint multiaddrs (only reachable classes kept — Onion3 / PublicDirect
/// / Circuit; LAN addrs are dropped rather than trusted). Errors on any
/// bounds/schema/expiry/signature failure.
pub fn verify_and_canonicalize(record: &EndpointRecord) -> Result<Vec<Multiaddr>> {
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
    Ok(out)
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
        let eps = verify_and_canonicalize(&rec).unwrap();
        assert_eq!(eps.len(), 1);
    }

    #[test]
    fn forged_signature_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let other = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.signature = hex::encode(other.sign(b"garbage").unwrap());
        assert!(verify_and_canonicalize(&rec).is_err());
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec!["/ip4/1.2.3.4/tcp/4001".into()]).unwrap();
        rec.endpoints.push("/ip4/9.9.9.9/tcp/4001".into());
        assert!(verify_and_canonicalize(&rec).is_err());
    }

    #[test]
    fn expired_rejected() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec![]).unwrap();
        rec.expires_at = chrono::Utc::now().timestamp() - 1;
        assert!(verify_and_canonicalize(&rec).is_err());
    }

    #[test]
    fn bound_enforced() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut rec = sign_record(&key, vec![]).unwrap();
        rec.endpoints = (0..9).map(|i| format!("/ip4/10.0.0.{}/tcp/1", i)).collect();
        assert!(verify_and_canonicalize(&rec).is_err());
    }
}
