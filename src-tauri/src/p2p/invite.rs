//! Invite string format for cold-start contact exchange.
//!
//! An invite bundles a peer id with the addresses where it can be reached:
//!
//! ```text
//! noid:<peerId>@<multiaddr1>,<multiaddr2>,...
//! ```
//!
//! The `@addrs` part is optional — a bare `noid:<peerId>` (or a bare peer id /
//! multiaddr without the prefix) falls back to DHT lookup. Address hints let a
//! completely fresh node reach its first peer without any bootstrap: the addr
//! may be direct (`/ip4/.../p2p/<peer>`) or relayed
//! (`<relay-addr>/p2p-circuit/p2p/<peer>`).

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

/// Prefix marking a Noid invite string.
pub const INVITE_PREFIX: &str = "noid:";

/// Maximum number of address hints accepted in one invite.
/// Parsing is more tolerant than building — older builds and invites edited
/// by hand may carry a few extra hints; the dialer just tries them in order.
const MAX_PARSE_ADDRS: usize = 10;

/// Maximum number of address hints we put into a generated invite.
/// Capped so the string stays copy-paste friendly and parses everywhere.
const MAX_BUILD_ADDRS: usize = 4;

/// A parsed invite: target peer id plus optional dialable address hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInvite {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

/// Last `/p2p/<peer>` protocol in a multiaddr, if any.
fn last_p2p_peer(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().filter_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    }).last()
}

/// Parse a user-provided invite/contact string.
///
/// Accepted forms:
/// - `noid:<peerId>@<addr1>,<addr2>` — peer plus explicit address hints
/// - `noid:<peerId>` or bare `<peerId>` — peer only, resolved via DHT
/// - bare `<multiaddr>` containing `/p2p/<peer>` — addr carrying its peer id
pub fn parse_invite(input: &str) -> Result<ParsedInvite, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Empty invite".into());
    }

    if let Some(body) = input.strip_prefix(INVITE_PREFIX) {
        let (peer_part, addrs_part) = match body.split_once('@') {
            Some((p, a)) => (p.trim(), Some(a)),
            None => (body.trim(), None),
        };
        let peer = peer_part
            .parse::<PeerId>()
            .map_err(|_| "Invite has invalid peer id".to_string())?;

        let mut addrs = Vec::new();
        if let Some(part) = addrs_part {
            for raw in part.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if addrs.len() >= MAX_PARSE_ADDRS {
                    return Err(format!("Too many addresses in invite (max {MAX_PARSE_ADDRS})"));
                }
                let mut addr = raw
                    .parse::<Multiaddr>()
                    .map_err(|_| format!("Invalid address in invite: {raw}"))?;
                match last_p2p_peer(&addr) {
                    Some(id) if id != peer => {
                        return Err("Address peer id does not match invite peer".into());
                    }
                    None => addr = addr.with(Protocol::P2p(peer)),
                    _ => {}
                }
                addrs.push(addr.to_string());
            }
        }
        return Ok(ParsedInvite { peer_id: peer.to_string(), addrs });
    }

    if let Ok(peer) = input.parse::<PeerId>() {
        return Ok(ParsedInvite { peer_id: peer.to_string(), addrs: Vec::new() });
    }
    if let Ok(addr) = input.parse::<Multiaddr>() {
        if let Some(peer) = last_p2p_peer(&addr) {
            return Ok(ParsedInvite {
                peer_id: peer.to_string(),
                addrs: vec![addr.to_string()],
            });
        }
        return Err("Address must contain a /p2p/<peerId> component".into());
    }
    Err("Not a valid invite, peer id or address".into())
}

/// True when the addr's IP/DNS part is publicly routable.
/// A13: delegates to `ip_scope` — plain `is_private()` missed carrier-CGNAT
/// ranges (100.64/10, 25/8, 26/8), sorting undialable carrier addresses
/// first in out-of-band invites.
pub(crate) fn is_public_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => {
            crate::p2p::classify_peer_addr::ip_scope(std::net::IpAddr::V4(ip))
                == crate::p2p::addr_class::AddrClass::PublicDirect
        }
        Protocol::Ip6(ip) => {
            crate::p2p::classify_peer_addr::ip_scope(std::net::IpAddr::V6(ip))
                == crate::p2p::addr_class::AddrClass::PublicDirect
        }
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => true,
        _ => false,
    })
}

/// Build an invite string for `peer_id` reachable at `addrs`.
/// `addrs` should already be filtered for the active privacy mode.
///
/// Each addr is normalized to end with `/p2p/<peer_id>` — relayed addrs from
/// `NewListenAddr` stop at `/p2p-circuit` and need our own peer id appended
/// so the receiver can dial them back. Duplicates are removed, public
/// addresses come first (a remote peer cannot use our LAN hints anyway —
/// they are only kept as a fallback for same-LAN sharing), and the whole
/// list is capped at `MAX_BUILD_ADDRS`.
pub fn build_invite(peer_id: &PeerId, addrs: &[String]) -> String {
    let normalized: Vec<String> = addrs
        .iter()
        .map(|a| match a.parse::<Multiaddr>() {
            Ok(addr) if last_p2p_peer(&addr) == Some(*peer_id) => a.clone(),
            Ok(addr) => addr.with(Protocol::P2p(*peer_id)).to_string(),
            // Unparseable entry — keep as-is, the receiver validates anyway.
            Err(_) => a.clone(),
        })
        .collect();
    if normalized.is_empty() {
        return format!("{INVITE_PREFIX}{peer_id}");
    }
    let mut seen = std::collections::HashSet::new();
    let (mut public, mut local): (Vec<String>, Vec<String>) =
        normalized.iter().cloned().partition(|a| {
            a.parse::<Multiaddr>().map(|m| is_public_addr(&m)).unwrap_or(false)
        });
    public.retain(|a| seen.insert(a.clone()));
    local.retain(|a| seen.insert(a.clone()));
    let best: Vec<String> = public
        .into_iter()
        .chain(local)
        .take(MAX_BUILD_ADDRS)
        .collect();
    format!("{INVITE_PREFIX}{peer_id}@{}", best.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn parses_full_invite() {
        let p = peer();
        let s = format!("noid:{p}@/ip4/1.2.3.4/tcp/4001/p2p/{p}");
        let inv = parse_invite(&s).unwrap();
        assert_eq!(inv.peer_id, p.to_string());
        assert_eq!(inv.addrs.len(), 1);
        assert!(inv.addrs[0].contains(&format!("/p2p/{p}")));
    }

    #[test]
    fn parses_bare_peer() {
        let p = peer();
        for s in [format!("noid:{p}"), p.to_string()] {
            let inv = parse_invite(&s).unwrap();
            assert_eq!(inv.peer_id, p.to_string());
            assert!(inv.addrs.is_empty());
        }
    }

    #[test]
    fn parses_bare_multiaddr() {
        let p = peer();
        let s = format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}");
        let inv = parse_invite(&s).unwrap();
        assert_eq!(inv.peer_id, p.to_string());
        assert_eq!(inv.addrs, vec![s]);
    }

    #[test]
    fn parses_relayed_addr() {
        let relay = peer();
        let p = peer();
        let s = format!(
            "noid:{p}@/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{p}"
        );
        let inv = parse_invite(&s).unwrap();
        assert_eq!(inv.addrs.len(), 1);
        assert!(inv.addrs[0].contains("p2p-circuit"));
    }

    #[test]
    fn addr_without_p2p_gets_peer_appended() {
        let p = peer();
        let s = format!("noid:{p}@/ip4/1.2.3.4/tcp/4001");
        let inv = parse_invite(&s).unwrap();
        assert!(inv.addrs[0].ends_with(&format!("/p2p/{p}")));
    }

    #[test]
    fn rejects_mismatched_peer() {
        let p = peer();
        let other = peer();
        let s = format!("noid:{p}@/ip4/1.2.3.4/tcp/4001/p2p/{other}");
        assert!(parse_invite(&s).is_err());
    }

    #[test]
    fn rejects_too_many_addrs() {
        let p = peer();
        let addrs = (0..=MAX_PARSE_ADDRS)
            .map(|_| format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_invite(&format!("noid:{p}@{addrs}")).is_err());
    }

    #[test]
    fn accepts_six_addrs() {
        // Invites from builds that emitted duplicated/loopback hints must
        // still parse — the dialer tries them in order.
        let p = peer();
        let addrs = (0..6)
            .map(|_| format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}"))
            .collect::<Vec<_>>()
            .join(",");
        let inv = parse_invite(&format!("noid:{p}@{addrs}")).unwrap();
        assert_eq!(inv.addrs.len(), 6);
    }

    #[test]
    fn build_dedups_and_prefers_public() {
        let p = peer();
        let relay = peer();
        let addrs = vec![
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}"),
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}"), // duplicate — dropped
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay}/p2p-circuit"), // local
            format!("/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit"), // public relayed
        ];
        let built = build_invite(&p, &addrs);
        let inv = parse_invite(&built).unwrap();
        // Public addrs first, dedup applied, local kept as LAN fallback.
        assert_eq!(inv.addrs.len(), 3);
        assert!(inv.addrs[0].contains("/ip4/1.2.3.4/"));
        assert!(inv.addrs[1].contains("/ip4/5.6.7.8/"));
        assert!(inv.addrs[2].contains("/ip4/127.0.0.1/"));
    }

    #[test]
    fn build_caps_at_max() {
        let p = peer();
        let addrs: Vec<String> = (0..8)
            .map(|i| format!("/ip4/1.2.3.{i}/tcp/4001/p2p/{p}"))
            .collect();
        let inv = parse_invite(&build_invite(&p, &addrs)).unwrap();
        assert_eq!(inv.addrs.len(), MAX_BUILD_ADDRS);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_invite("").is_err());
        assert!(parse_invite("hello world").is_err());
        assert!(parse_invite("noid:not-a-peer").is_err());
        assert!(parse_invite("/ip4/1.2.3.4/tcp/4001").is_err());
    }

    #[test]
    fn build_roundtrips() {
        let p = peer();
        let addrs = vec![format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}")];
        let inv = parse_invite(&build_invite(&p, &addrs)).unwrap();
        assert_eq!(inv.peer_id, p.to_string());
        assert_eq!(inv.addrs, addrs);
    }

    #[test]
    fn build_bare_when_no_addrs() {
        let p = peer();
        assert_eq!(build_invite(&p, &[]), format!("noid:{p}"));
    }

    #[test]
    fn build_appends_peer_to_relayed_addr() {
        let p = peer();
        let relay = peer();
        // Relayed addrs from NewListenAddr stop at /p2p-circuit.
        let addrs = vec![format!("/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit")];
        let built = build_invite(&p, &addrs);
        let inv = parse_invite(&built).unwrap();
        assert!(inv.addrs[0].ends_with(&format!("p2p-circuit/p2p/{p}")));
    }
}
