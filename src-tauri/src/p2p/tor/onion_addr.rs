//! Onion3 multiaddr validation for the Noid canonical form
//! `/onion3/<56-char-v3-host>:<vport>/p2p/<PeerId>`.
//!
//! Accepted: exactly one `Protocol::Onion3` with a nonzero port, optionally
//! followed by `/p2p/<peer>`. Rejected: v2/malformed, port 0, extra
//! transports (nested circuit, tcp/udp wrappers) — onion3 is terminal.
//!
//! `.onion` inside `/dns*` forms is normalized by callers into onion3 BEFORE
//! DNS resolution ever happens — this module only sees already-onion3 input.

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};

/// Virtual port Noid onion services accept stream requests on.
pub const ONION_VPORT: u16 = 4020;

/// Parsed canonical onion address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOnion {
    /// 56-char lowercase v3 host without `.onion` suffix.
    pub host: String,
    /// Virtual port (must be `ONION_VPORT` for Noid services).
    pub port: u16,
    /// Optional expected peer after `/p2p/`.
    pub peer_id: Option<PeerId>,
}

/// RFC 4648 base32 (lowercase, no padding): 35 bytes → 56 chars.
fn base32_nopad(data: &[u8; 35]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(56);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// Parse and validate a multiaddr: must be exactly `/onion3/h:p` optionally
/// followed by `/p2p/<peer>` — nothing else. Returns `None` for non-onion3
/// input (caller classifies it elsewhere) or malformed onion3.
pub fn parse(addr: &Multiaddr) -> Option<ParsedOnion> {
    let mut protos = addr.iter();
    let Some(Protocol::Onion3(onion)) = protos.next() else {
        return None;
    };
    if onion.port() == 0 {
        return None;
    }
    let host = base32_nopad(onion.hash());
    let peer_id = match protos.next() {
        None => None,
        Some(Protocol::P2p(p)) => Some(p),
        Some(_) => return None,
    };
    if protos.next().is_some() {
        return None;
    }
    Some(ParsedOnion {
        host,
        port: onion.port(),
        peer_id,
    })
}

/// Whether the addr is onion3-shaped at all (vs simply non-onion).
pub fn is_onion(addr: &Multiaddr) -> bool {
    matches!(addr.iter().next(), Some(Protocol::Onion3(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_parses() {
        let a: Multiaddr = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:4020/p2p/12D3KooWGRvmM9hQ8p4YHvLkWjKZ8nQpJ3kY4mZ2v1g2X3c4D5e6".parse().unwrap();
        let p = parse(&a).expect("canonical onion3 must parse");
        assert_eq!(p.port, 4020);
        assert_eq!(p.host, "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd");
        assert!(p.peer_id.is_some());
    }

    #[test]
    fn non_onion_rejected() {
        let a: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        assert!(parse(&a).is_none());
    }

    #[test]
    fn port_zero_rejected() {
        // multiaddr's own parser refuses onion3 port 0 — the invariant is
        // enforced before our parser ever sees it.
        assert!("/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0"
            .parse::<Multiaddr>()
            .is_err());
    }

    #[test]
    fn extra_protocol_rejected() {
        let a: Multiaddr = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:4020/tcp/80".parse().unwrap();
        assert!(parse(&a).is_none());
    }

    #[test]
    fn base32_len() {
        assert_eq!(base32_nopad(&[0xff; 35]).len(), 56);
    }
}
