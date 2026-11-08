//! Synchronous UDP/QUIC hole-punching (`punch_assist`) for Case 2 (Mobile CGNAT).
//!
//! Why this is needed on mobile LTE (CGNAT):
//! Even when Peer A knows its own external `IP_A:Port_A` via STUN Keepalive,
//! its carrier's Address/Port-Restricted CGNAT firewall drops incoming UDP
//! packets from Peer B (`IP_B:Port_B`) until Peer A's QUIC listener socket
//! has transmitted at least one outbound UDP datagram toward `IP_B:Port_B`.
//!
//! When both nodes run [`spawn_udp_punch_burst`] toward each other's external
//! address (learned either via Mutual Invite or via [`crate::p2p::cgnat_rendezvous`]):
//! 1. Both QUIC listener sockets (`4020/udp`) emit lightweight 32-byte UDP
//!    knock packets toward the peer's base port and a small port fan
//!    `[port - 4 .. port + 12]` (covering sequential-delta CGNAT allocations).
//! 2. Both carrier CGNATs record an outbound flow `(local_4020 <-> remote_ip:port)`
//!    and open the return pinhole.
//! 3. `swarm.dial` over `/ip4/<remote_ip>/udp/<port>/quic-v1` immediately
//!    rides through the opened pinhole and establishes a direct QUIC session!

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Extract a target IPv4/IPv6 UDP or TCP `SocketAddr` from a Multiaddr if it is
/// a public/WAN address (ignores loopback and RFC1918 LAN addresses).
pub fn extract_wan_socket_addr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    for p in addr.iter() {
        match p {
            Protocol::Ip4(v4) => {
                if v4.is_loopback() || v4.is_private() || v4.is_unspecified() || v4.is_link_local()
                {
                    return None;
                }
                ip = Some(IpAddr::V4(v4));
            }
            Protocol::Ip6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return None;
                }
                ip = Some(IpAddr::V6(v6));
            }
            Protocol::Udp(u) | Protocol::Tcp(u) => {
                if u == 0 {
                    return None;
                }
                port = Some(u);
            }
            Protocol::P2pCircuit => return None,
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

/// Compute the candidate port fan around `base_port` to pierce sequential
/// CGNAT port allocations (`base`, then `+1..+12`, `-1..-4`).
pub fn candidate_port_fan(base_port: u16) -> Vec<u16> {
    let mut ports = Vec::with_capacity(17);
    ports.push(base_port);
    for d in 1..=12u16 {
        if let Some(p) = base_port.checked_add(d) {
            if p > 1024 {
                ports.push(p);
            }
        }
    }
    for d in 1..=4u16 {
        if let Some(p) = base_port.checked_sub(d) {
            if p > 1024 {
                ports.push(p);
            }
        }
    }
    ports
}

/// Send a single wave of UDP hole-punch knock datagrams from `socket` toward
/// `target` and its port fan.
pub fn send_punch_wave(socket: &UdpSocket, target: SocketAddr, include_fan: bool) -> usize {
    // 20-byte RFC 5389 STUN Binding Request header — looks like standard
    // WebRTC/ICE hole-punch traffic to carrier DPI and is harmlessly ignored
    // by `quinn` if it lands on the remote QUIC endpoint after the hole opens.
    let pkt = libp2p_quic::stun_hook::build_binding_request(*b"NOIDPUNCH001");
    let mut sent = 0;
    let ports = if include_fan {
        candidate_port_fan(target.port())
    } else {
        vec![target.port()]
    };
    for port in ports {
        let dst = SocketAddr::new(target.ip(), port);
        if socket.send_to(&pkt, dst).is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Spawn a bounded background UDP hole-punch burst from our active QUIC
/// listener socket toward `target` (8 waves over ~3.5 seconds).
///
/// Opens the outbound CGNAT pinhole for `target.ip()` so the simultaneous
/// QUIC handshake from the remote peer is let through by our carrier firewall.
pub fn spawn_udp_punch_burst(target: SocketAddr, include_fan: bool) {
    let Some(sock) = libp2p_quic::stun_hook::clone_listener_udp_socket(target.is_ipv6()) else {
        return;
    };
    tokio::spawn(async move {
        for wave in 0..8u8 {
            // Fan on the first 4 waves, then focus on the exact base port.
            send_punch_wave(&sock, target, include_fan && wave < 4);
            tokio::time::sleep(Duration::from_millis(450)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_wan_addr_and_skips_private_or_circuit() {
        let wan: Multiaddr = "/ip4/85.140.1.2/udp/4020/quic-v1".parse().unwrap();
        assert_eq!(
            extract_wan_socket_addr(&wan),
            Some("85.140.1.2:4020".parse().unwrap())
        );

        let lan: Multiaddr = "/ip4/192.168.1.5/udp/4020/quic-v1".parse().unwrap();
        assert!(extract_wan_socket_addr(&lan).is_none());

        let circuit: Multiaddr =
            "/ip4/85.140.1.2/tcp/4020/p2p/12D3KooWHxVSRHq1oP2Nx5U6dRTrdEnfLkR85EV7akHd7xX5sw8D/p2p-circuit"
                .parse()
                .unwrap();
        assert!(extract_wan_socket_addr(&circuit).is_none());
    }

    #[test]
    fn punch_wave_delivers_datagram_to_target() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sent = send_punch_wave(&tx, rx_addr, false);
        assert_eq!(sent, 1);

        let mut buf = [0u8; 32];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(n, 20);
    }
}
