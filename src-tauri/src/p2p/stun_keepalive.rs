//! STUN external address discovery & 20-second `PersistentKeepalive` (RFC 5389).
//!
//! Solves the "First Node Behind NAT" problem:
//! 1. Right when the QUIC UDP socket binds (even with 0 peers and 0 relays),
//!    `libp2p_quic::stun_hook` probes two public STUN servers from that exact
//!    socket and learns the external `IP:UDP_port` + NAT type (Cone vs Symmetric).
//! 2. Every 20 seconds (`STUN_KEEPALIVE_INTERVAL`), [`tick_stun_keepalive`]
//!    sends 20-byte UDP Binding Requests from the cloned QUIC listener socket
//!    to keep the router/CGNAT mapping open (WireGuard `PersistentKeepalive`
//!    equivalent) and refreshes the mapping if the network changed.
//! 3. Converts the STUN-mapped socket address into a dialable QUIC [`Multiaddr`]
//!    (`/ip4/<ip>/udp/<port>/quic-v1`) so `get_my_invite` always contains a
//!    real external address instead of a bare PeerId.

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use libp2p_quic::stun_hook::{
    self, build_binding_request, StunMapping, StunNatKind,
};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// WireGuard-style keepalive cadence — shorter than the 30-45s UDP timeout
/// on mobile CGNATs (Tele2 / MTS / MegaFon) and home routers.
pub const STUN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// Human-readable label for the NAT mapping classification.
pub fn nat_kind_label(kind: Option<StunNatKind>, has_port_forward: bool) -> &'static str {
    if has_port_forward {
        return "public_port_mapped";
    }
    match kind {
        Some(StunNatKind::Cone) => "stun_cone",
        Some(StunNatKind::Symmetric { .. } | StunNatKind::AddressDependent) => "stun_symmetric",
        Some(StunNatKind::SingleSample) => "stun_mapped",
        None => "unknown",
    }
}

/// Format an observed [`StunMapping`] into a `/ip4/<ip>/udp/<port>/quic-v1` Multiaddr.
pub fn mapping_to_quic_multiaddr(mapping: &StunMapping) -> Multiaddr {
    let mut m = Multiaddr::empty();
    match mapping.external_addr.ip() {
        IpAddr::V4(v4) => m.push(Protocol::Ip4(v4)),
        IpAddr::V6(v6) => m.push(Protocol::Ip6(v6)),
    }
    m.push(Protocol::Udp(mapping.external_addr.port()));
    m.push(Protocol::QuicV1);
    m
}

/// Return the currently observed STUN mapping from the QUIC listener socket,
/// or perform an on-demand probe if none was recorded yet.
pub fn current_or_probe_mapping(fallback_local_port: u16) -> Option<StunMapping> {
    if std::env::var_os("NOID_DISABLE_STUN").is_some() {
        return stun_hook::observed_stun_mapping();
    }
    if let Some(m) = stun_hook::observed_stun_mapping() {
        return Some(m);
    }
    let generation = stun_hook::listener_generation(false)?;
    // Fallback probe on an ephemeral socket to learn at least our public IP
    // and NAT behaviour (Cone vs Symmetric) if the initial hook raced network up.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let mut probed = stun_hook::probe_socket_sync(&sock, fallback_local_port)?;
    // On Cone NAT with port preservation, the QUIC listener's external port
    // matches `fallback_local_port` when `fallback_local_port != 0`.
    if matches!(probed.nat_kind, StunNatKind::Cone) && fallback_local_port != 0 {
        probed.external_addr.set_port(fallback_local_port);
    }
    stun_hook::set_observed_stun_mapping(generation, probed.clone()).then_some(probed)
}

/// Periodic 20-second keepalive tick:
/// - Fires 20-byte STUN Binding Requests from the active QUIC listener socket
///   so the router/CGNAT resets its UDP inactivity timer.
/// - Returns the active [`StunMapping`] (if available) so `P2PNode` can ensure
///   the QUIC external address is registered for invites and rendezvous.
pub fn tick_stun_keepalive(local_quic_port: u16) -> Option<StunMapping> {
    let _sent = stun_hook::send_keepalive_pulses();
    current_or_probe_mapping(local_quic_port)
}

/// Probe a specific STUN server address (used by unit tests with a local mock
/// STUN reflector).
pub fn probe_single_server(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Option<SocketAddr> {
    socket.set_read_timeout(Some(timeout)).ok()?;
    let tx_id: [u8; 12] = rand::random();
    let req = build_binding_request(tx_id);
    socket.send_to(&req, server).ok()?;
    let mut buf = [0u8; 128];
    let (n, from) = socket.recv_from(&mut buf).ok()?;
    if from != server {
        return None;
    }
    stun_hook::parse_binding_response(&buf[..n], Some(&tx_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p_quic::stun_hook::{parse_binding_response, STUN_MAGIC_COOKIE};
    use std::net::Ipv4Addr;

    /// Build a synthetic RFC 5389 Binding Success Response with `XOR-MAPPED-ADDRESS`.
    fn build_mock_xor_response(tx_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let IpAddr::V4(ip) = mapped.ip() else {
            panic!("ipv4 only in mock");
        };
        let port = mapped.port();
        let xport = port ^ u16::from_be_bytes([STUN_MAGIC_COOKIE[0], STUN_MAGIC_COOKIE[1]]);
        let oct = ip.octets();
        let xip = [
            oct[0] ^ STUN_MAGIC_COOKIE[0],
            oct[1] ^ STUN_MAGIC_COOKIE[1],
            oct[2] ^ STUN_MAGIC_COOKIE[2],
            oct[3] ^ STUN_MAGIC_COOKIE[3],
        ];
        let mut msg = Vec::with_capacity(32);
        // Binding Success Response (0x0101), length 12 bytes
        msg.extend_from_slice(&[0x01, 0x01, 0x00, 12]);
        msg.extend_from_slice(&STUN_MAGIC_COOKIE);
        msg.extend_from_slice(&tx_id);
        // Attribute XOR-MAPPED-ADDRESS (0x0020), length 8
        msg.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
        msg.push(0x00);
        msg.push(0x01); // IPv4 family
        msg.extend_from_slice(&xport.to_be_bytes());
        msg.extend_from_slice(&xip);
        msg
    }

    #[test]
    fn stun_roundtrip_against_local_mock_reflector() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let expected: SocketAddr = "85.140.12.34:54321".parse().unwrap();

        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, client_addr) = srv.recv_from(&mut buf).unwrap();
            assert_eq!(n, 20);
            let mut tx = [0u8; 12];
            tx.copy_from_slice(&buf[8..20]);
            let resp = build_mock_xor_response(tx, expected);
            srv.send_to(&resp, client_addr).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let got = probe_single_server(&client, srv_addr, Duration::from_secs(2)).unwrap();
        assert_eq!(got, expected);

        let mapping = StunMapping {
            external_addr: got,
            local_port: 4020,
            nat_kind: StunNatKind::Cone,
        };
        let maddr = mapping_to_quic_multiaddr(&mapping);
        assert_eq!(maddr.to_string(), "/ip4/85.140.12.34/udp/54321/quic-v1");
        assert_eq!(nat_kind_label(Some(StunNatKind::Cone), false), "stun_cone");
        assert_eq!(
            nat_kind_label(Some(StunNatKind::Cone), true),
            "public_port_mapped"
        );
    }

    #[test]
    fn rejects_mismatched_transaction_id() {
        let tx_a = [1u8; 12];
        let tx_b = [2u8; 12];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4020);
        let pkt = build_mock_xor_response(tx_a, addr);
        assert!(parse_binding_response(&pkt, Some(&tx_b)).is_none());
        assert_eq!(parse_binding_response(&pkt, Some(&tx_a)), Some(addr));
    }
}
