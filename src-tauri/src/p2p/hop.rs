//! META-05: two-hop privacy relay — `/noid-hop/1.0.0` request-response.
//!
//! Plain request-response forwarding, onion-style: the sender nests one
//! `HopRequest` inside another. The ENTRY relay sees "forward to the exit
//! relay" — never the destination. The EXIT relay sees "forward an opaque
//! `/noid` frame to the destination" — never the origin (the Noise
//! connection it answers belongs to the entry). The payload itself is
//! already ratchet E2EE, so neither relay reads it.
//!
//! `proto` tags the payload: `1` = a nested HopRequest (forward on the
//! hop protocol), `0` = a serialized `NoidMessage` (forward on `/noid`).
//! The response rides the same nesting backwards.
use serde::{Deserialize, Serialize};

/// Forwarded frame — `next` is a PeerId string; `payload` is opaque to
/// every relay on the path (only the endpoints parse it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopRequest {
    pub next: String,
    pub proto: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopResponse {
    pub payload: Vec<u8>,
}

/// `payload` is a serialized `NoidMessage` — last hop speaks `/noid`.
pub const PROTO_NOID: u8 = 0;
/// `payload` is a serialized `HopRequest` — intermediate hops recurse.
pub const PROTO_HOP: u8 = 1;

/// Hard cap on a forwarded frame — requests larger than this are refused
/// before any parsing. Matches the mailbox envelope budget class.
pub const MAX_HOP_PAYLOAD: usize = 64 * 1024;
/// Pending forward correlation entries — bounded against a flood of
/// inbound hop requests pinning response channels.
pub const MAX_HOP_PENDING: usize = 1024;

/// Wrap `inner` (already-serialized NoidMessage or HopRequest) for
/// `chain = [entry, exit, …]`: the RETURNED frame is sent to `relays[0]`
/// and names `relays[1]` as its next hop — each relay only learns its
/// successor, never the origin or the final destination.
/// `[A,B] → {next:B, proto:HOP, payload:{next:dest, proto:noid, inner}}`
/// sent to A; `[A] → {next:dest, proto:noid}` — a 1-hop forward.
pub fn wrap(dest: &str, relays: &[String], noid_proto: u8, inner: Vec<u8>) -> Result<HopRequest, String> {
    if relays.is_empty() {
        return Err("empty relay chain".to_string());
    }
    let mut frame = HopRequest {
        next: dest.to_string(),
        proto: noid_proto,
        payload: inner,
    };
    for relay in relays[1..].iter().rev() {
        frame = HopRequest {
            next: relay.clone(),
            proto: PROTO_HOP,
            payload: serde_json::to_vec(&frame).map_err(|e| e.to_string())?,
        };
    }
    Ok(frame)
}

/// Unwrap one layer — returns `(next_peer, inner_proto, inner_payload)`
/// or an error string for malformed frames.
pub fn unwrap(frame: &HopRequest) -> Result<(String, u8, Vec<u8>), String> {
    if frame.proto != PROTO_NOID && frame.proto != PROTO_HOP {
        return Err(format!("unknown hop proto {}", frame.proto));
    }
    if frame.payload.len() > MAX_HOP_PAYLOAD {
        return Err("hop payload exceeds limit".to_string());
    }
    Ok((frame.next.clone(), frame.proto, frame.payload.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hop_nesting() {
        let relays = vec!["A".to_string(), "B".to_string()];
        let frame = wrap("DEST", &relays, PROTO_NOID, b"hello".to_vec()).unwrap();
        // Outer: entry A sees only "forward to B".
        assert_eq!(frame.next, "B");
        assert_eq!(frame.proto, PROTO_HOP);
        let inner: HopRequest = serde_json::from_slice(&frame.payload).unwrap();
        // B sees only "forward NoidMessage to DEST".
        assert_eq!(inner.next, "DEST");
        assert_eq!(inner.proto, PROTO_NOID);
        assert_eq!(inner.payload, b"hello");
    }

    #[test]
    fn malformed_rejected() {
        let bad = HopRequest { next: "x".into(), proto: 9, payload: vec![] };
        assert!(unwrap(&bad).is_err());
        let big = HopRequest { next: "x".into(), proto: 0, payload: vec![0; MAX_HOP_PAYLOAD + 1] };
        assert!(unwrap(&big).is_err());
    }
}
