use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use crate::p2p::addr_class::AddrClass;

pub(crate) fn ip_scope(ip: std::net::IpAddr) -> AddrClass {
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() || v4.is_broadcast() {
                return AddrClass::Local;
            }
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64; // 100.64.0.0/10
            // Carrier-internal ranges abused as CGNAT space (not RFC1918 but
            // unreachable from the public internet): 25/8 (UK MoD) and 26/8
            // (US DoD) are used by mobile operators — observed Tele2 handing
            // out 26.x device addrs. Treating them as PublicDirect poisons
            // the DHT with undialable addrs.
            let carrier_cgnat = o[0] == 25 || o[0] == 26;
            if v4.is_private() || v4.is_link_local() || cgnat || carrier_cgnat {
                return AddrClass::Lan;
            }
            AddrClass::PublicDirect
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return AddrClass::Local;
            }
            let seg = v6.segments()[0];
            let link_local = (seg & 0xffc0) == 0xfe80;
            let ula = (seg & 0xfe00) == 0xfc00; // fc00::/7
            if link_local || ula {
                return AddrClass::Lan;
            }
            AddrClass::PublicDirect
        }
    }
}

/// Classify `addr` as a candidate address for `target`.
///
/// Structural rules: at most one `/p2p-circuit`; a circuit must carry a relay
/// peer id before the circuit marker and terminate at `target`; `/tcp/0` is
/// not a dialable port; an addr without any transport is useless.
/// Reachability is judged on the FIRST ip/dns hop — for a circuit that is the
/// relay's transport, for a direct addr the peer's own.
pub fn classify_peer_addr(addr: &Multiaddr, target: &PeerId) -> AddrClass {
    let mut circuits = 0u8;
    let mut p2p_ids: Vec<PeerId> = Vec::new();
    let mut scope: Option<AddrClass> = None;
    let mut has_transport = false;

    for p in addr.iter() {
        match p {
            Protocol::P2pCircuit => {
                circuits += 1;
            }
            Protocol::P2p(id) => p2p_ids.push(id),
            Protocol::Ip4(v4) => {
                if scope.is_none() {
                    scope = Some(ip_scope(std::net::IpAddr::V4(v4)));
                }
            }
            Protocol::Ip6(v6) => {
                if scope.is_none() {
                    scope = Some(ip_scope(std::net::IpAddr::V6(v6)));
                }
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)
            | Protocol::Dnsaddr(_) => {
                if scope.is_none() {
                    scope = Some(AddrClass::PublicDirect);
                }
            }
            Protocol::Tcp(0) | Protocol::Udp(0) => return AddrClass::Malformed,
            Protocol::Tcp(_) | Protocol::Udp(_) => has_transport = true,
            _ => {}
        }
    }

    if circuits > 1 {
        return AddrClass::Malformed;
    }

    if circuits == 1 {
        // Valid peer circuit: <relay-transport>/p2p/<relay>/p2p-circuit/p2p/<target>.
        // Fewer than two /p2p/ ids means either a bare reservation-listen form
        // (no destination) or a circuit without a relay id — both are not
        // dialable peer addresses.
        if p2p_ids.len() != 2 || p2p_ids.last() != Some(target) {
            return AddrClass::Malformed;
        }
        if !has_transport {
            return AddrClass::Malformed;
        }
        return match scope.unwrap_or(AddrClass::Malformed) {
            AddrClass::PublicDirect => AddrClass::Circuit,
            AddrClass::Lan => AddrClass::Lan,
            _ => AddrClass::Malformed,
        };
    }

    // Direct addr: must have transport; terminal /p2p/ (if present) is target.
    if !has_transport {
        return AddrClass::Malformed;
    }
    if let Some(last) = p2p_ids.last() {
        if *last != *target {
            return AddrClass::Malformed;
        }
    }
    scope.unwrap_or(AddrClass::Malformed)
}
