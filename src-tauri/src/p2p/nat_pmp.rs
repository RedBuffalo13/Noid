//! NAT-PMP (RFC 6886) automatic port mapping for Case 1 (Wi-Fi Behind Router NAT).
//!
//! Many home/office routers (Keenetic, MikroTik, Apple AirPort, OpenWrt)
//! disable UPnP IGD by default for security but keep **NAT-PMP / PCP** enabled
//! on UDP port `5351` of the default LAN gateway (`192.168.x.1` / `10.x.x.1`).
//!
//! Protocol summary (RFC 6886):
//! - External IP request (2 bytes): `[0x00, 0x00]` -> 12-byte response
//!   `[0x00, 0x80, result(2), epoch(4), ext_ip(4)]`.
//! - Port mapping request (12 bytes):
//!   `[0x00, op (1=UDP, 2=TCP), 0x00, 0x00, internal_port(2), external_port(2), lifetime_secs(4)]`
//!   -> 16-byte response `[0x00, 0x80+op, result(2), epoch(4), internal_port(2), mapped_port(2), lifetime(4)]`.

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Standard NAT-PMP / PCP UDP port on the default LAN gateway.
pub const NAT_PMP_PORT: u16 = 5351;
/// Requested lease lifetime (1 hour, renewed every 20 minutes).
pub const LEASE_LIFETIME_SECS: u32 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpLease {
    pub external_ip: Ipv4Addr,
    pub udp_external_port: u16,
    pub tcp_external_port: Option<u16>,
    pub gateway: Ipv4Addr,
}

impl NatPmpLease {
    /// Convert the leased mapping into dialable public Multiaddrs (QUIC + TCP).
    pub fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        let mut out = Vec::with_capacity(2);
        let mut q = Multiaddr::empty();
        q.push(Protocol::Ip4(self.external_ip));
        q.push(Protocol::Udp(self.udp_external_port));
        q.push(Protocol::QuicV1);
        out.push(q);

        if let Some(tp) = self.tcp_external_port {
            let mut t = Multiaddr::empty();
            t.push(Protocol::Ip4(self.external_ip));
            t.push(Protocol::Tcp(tp));
            out.push(t);
        }
        out
    }
}

/// Build the 2-byte RFC 6886 External Address Request.
pub fn build_ext_ip_request() -> [u8; 2] {
    [0x00, 0x00]
}

/// Parse the 12-byte RFC 6886 External Address Response.
pub fn parse_ext_ip_response(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 12 || buf[0] != 0x00 || buf[1] != 0x80 {
        return None;
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return None;
    }
    let ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
    // 100.64.0.0/10 (CGNAT shared space, RFC 6598): a router behind carrier
    // NAT still answers NAT-PMP, but the leased "external" address is not
    // globally reachable — accepting it would produce a fake Public status.
    // (`Ipv4Addr::is_shared` is unstable on this toolchain — check the /10.)
    let is_cgnat_shared = ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 0x40;
    if ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || is_cgnat_shared
    {
        return None;
    }
    Some(ip)
}

/// Build the 12-byte RFC 6886 Port Mapping Request (`op`: `1` = UDP, `2` = TCP).
pub fn build_map_request(op: u8, internal_port: u16, external_port: u16, lifetime: u32) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    pkt[0] = 0x00;
    pkt[1] = op;
    pkt[4..6].copy_from_slice(&internal_port.to_be_bytes());
    pkt[6..8].copy_from_slice(&external_port.to_be_bytes());
    pkt[8..12].copy_from_slice(&lifetime.to_be_bytes());
    pkt
}

/// Parse the 16-byte RFC 6886 Port Mapping Response (`expected_op`: `1` = UDP, `2` = TCP).
pub fn parse_map_response(buf: &[u8], expected_op: u8) -> Option<u16> {
    if buf.len() < 16 || buf[0] != 0x00 || buf[1] != (0x80 | expected_op) {
        return None;
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return None;
    }
    let mapped_port = u16::from_be_bytes([buf[10], buf[11]]);
    if mapped_port == 0 {
        return None;
    }
    Some(mapped_port)
}

/// Infer candidate LAN gateway IPv4 addresses from our local LAN IP (`.1` and `.254`).
pub fn candidate_gateways_for_local_ip(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    if !local_ip.is_private() {
        return Vec::new();
    }
    let o = local_ip.octets();
    let mut out = vec![Ipv4Addr::new(o[0], o[1], o[2], 1)];
    if o[3] != 254 {
        out.push(Ipv4Addr::new(o[0], o[1], o[2], 254));
    }
    out
}

/// Discover our current primary private LAN IPv4 address by connecting a dummy
/// UDP socket toward a public IP (no packet is sent).
pub fn detect_local_lan_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if v4.is_private() => Some(v4),
        _ => None,
    }
}

/// Attempt a NAT-PMP lease against `gateway_addr` (`gateway_ip:5351`).
pub fn try_lease_at_gateway(
    gateway_addr: SocketAddr,
    internal_udp_port: u16,
    internal_tcp_port: u16,
    timeout: Duration,
) -> Option<NatPmpLease> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    // 1. Query external IPv4 address
    sock.send_to(&build_ext_ip_request(), gateway_addr).ok()?;
    let mut buf = [0u8; 32];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    let external_ip = parse_ext_ip_response(&buf[..n])?;

    // 2. Map UDP port (for QUIC)
    let udp_req = build_map_request(1, internal_udp_port, internal_udp_port, LEASE_LIFETIME_SECS);
    sock.send_to(&udp_req, gateway_addr).ok()?;
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    let udp_external_port = parse_map_response(&buf[..n], 1)?;

    // 3. Map TCP port (best-effort)
    let tcp_req = build_map_request(2, internal_tcp_port, internal_tcp_port, LEASE_LIFETIME_SECS);
    let tcp_external_port = if sock.send_to(&tcp_req, gateway_addr).is_ok() {
        sock.recv_from(&mut buf)
            .ok()
            .and_then(|(n, _)| parse_map_response(&buf[..n], 2))
    } else {
        None
    };

    let IpAddr::V4(gw_ip) = gateway_addr.ip() else {
        return None;
    };

    Some(NatPmpLease {
        external_ip,
        udp_external_port,
        tcp_external_port,
        gateway: gw_ip,
    })
}

/// Probe the current Wi-Fi / LAN default gateway for NAT-PMP support.
pub fn probe_lan_nat_pmp(internal_udp_port: u16, internal_tcp_port: u16) -> Option<NatPmpLease> {
    if internal_udp_port == 0 || std::env::var_os("NOID_DISABLE_STUN").is_some() {
        return None;
    }
    let local_ip = detect_local_lan_ipv4()?;
    for gw in candidate_gateways_for_local_ip(local_ip) {
        let addr = SocketAddr::new(IpAddr::V4(gw), NAT_PMP_PORT);
        if let Some(lease) = try_lease_at_gateway(
            addr,
            internal_udp_port,
            internal_tcp_port,
            Duration::from_millis(220),
        ) {
            return Some(lease);
        }
    }
    None
}

/// A lease only proves PUBLIC reachability when the router's WAN IP equals
/// our STUN-observed external IP. When they differ the ISP runs a second
/// NAT layer above the router (double NAT / ISP-side CGNAT) — the mapping
/// exists on the inner router but inbound packets can never reach it, so
/// marking the node Public would repeat the old fake-Public bug.
pub fn lease_confirms_public(lease: &NatPmpLease) -> bool {
    libp2p_quic::stun_hook::observed_stun_mapping()
        .map(|m| m.external_addr.ip() == IpAddr::V4(lease.external_ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_pmp_lease_roundtrip_against_mock_gateway() {
        let gw = UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw.local_addr().unwrap();

        std::thread::spawn(move || {
            let mut buf = [0u8; 32];
            // 1. Ext IP request
            let (n, client) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], &[0x00, 0x00]);
            let resp_ip = [0x00, 0x80, 0x00, 0x00, 0, 0, 1, 0, 93, 184, 216, 34];
            gw.send_to(&resp_ip, client).unwrap();

            // 2. UDP map request
            let (n, client) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(n, 12);
            assert_eq!(buf[1], 1);
            let mut resp_udp = [0u8; 16];
            resp_udp[0] = 0x00;
            resp_udp[1] = 0x81;
            resp_udp[8..10].copy_from_slice(&4020u16.to_be_bytes());
            resp_udp[10..12].copy_from_slice(&4020u16.to_be_bytes());
            resp_udp[12..16].copy_from_slice(&3600u32.to_be_bytes());
            gw.send_to(&resp_udp, client).unwrap();

            // 3. TCP map request
            let (n, client) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(n, 12);
            assert_eq!(buf[1], 2);
            let mut resp_tcp = [0u8; 16];
            resp_tcp[0] = 0x00;
            resp_tcp[1] = 0x82;
            resp_tcp[8..10].copy_from_slice(&4020u16.to_be_bytes());
            resp_tcp[10..12].copy_from_slice(&4020u16.to_be_bytes());
            resp_tcp[12..16].copy_from_slice(&3600u32.to_be_bytes());
            gw.send_to(&resp_tcp, client).unwrap();
        });

        let lease = try_lease_at_gateway(gw_addr, 4020, 4020, Duration::from_secs(2)).unwrap();
        assert_eq!(lease.external_ip, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(lease.udp_external_port, 4020);
        assert_eq!(lease.tcp_external_port, Some(4020));
        let addrs = lease.to_multiaddrs();
        assert_eq!(addrs[0].to_string(), "/ip4/93.184.216.34/udp/4020/quic-v1");
        assert_eq!(addrs[1].to_string(), "/ip4/93.184.216.34/tcp/4020");
    }
}
