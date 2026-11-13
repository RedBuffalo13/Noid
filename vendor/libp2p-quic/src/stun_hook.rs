//! Noid STUN hook & PersistentKeepalive socket registry for `libp2p-quic`.
//!
//! 1. Immediately after binding the IPv4 UDP listener socket (before `quinn`
//!    takes ownership of its read half), performs a fast RFC 5389 STUN
//!    Binding Request against two independent public STUN reflectors using
//!    IP literals (zero DNS latency). This learns the **exact** external
//!    `IP:UDP_port` mapped to our QUIC listener socket by the router/CGNAT,
//!    and classifies the NAT (Endpoint-Independent Cone vs Symmetric).
//! 2. Stores a `try_clone()` handle of the bound listener `UdpSocket` so
//!    Noid's 20-second `PersistentKeepalive` loop and `punch_assist` can
//!    transmit UDP packets directly from the QUIC listener's port without
//!    interfering with `quinn`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{atomic::AtomicU64, RwLock};
#[path = "stun_classify_samples.rs"]
mod classify_samples;
#[path = "stun_listener_generation.rs"]
mod listener_generation;
#[path = "stun_listener_registration.rs"]
mod listener_registration;
#[path = "stun_filter_probe.rs"]
mod filter_probe;
#[path = "stun_probe_reflectors.rs"]
mod probe_reflectors;
#[path = "stun_register_listener.rs"]
mod register_listener;
#[path = "stun_socket_slot.rs"]
mod socket_slot;
#[path = "stun_unregister_listener.rs"]
mod unregister_listener;

pub(crate) use classify_samples::classify_stun_samples;
pub use filter_probe::StunFilterKind;
pub(crate) use filter_probe::probe_filtering;
pub use listener_generation::listener_generation;
pub(crate) use listener_registration::ListenerSocketRegistration;
pub(crate) use probe_reflectors::probe_with_reflectors;
pub(crate) use register_listener::on_listener_socket_bound;
use socket_slot::RegisteredListenerSocket;

/// RFC 5389 magic cookie (`0x2112A442`).
pub const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// Well-known public STUN servers (IP literals — no DNS lookup required).
/// - Cloudflare `stun.cloudflare.com:3478` -> `162.159.207.0:3478`
/// - Google `stun.l.google.com:19302`      -> `74.125.250.129:19302`
/// - Google `stun1.l.google.com:19302`     -> `142.250.82.127:19302`
pub const PUBLIC_STUN_SERVERS: &[SocketAddr] = &[
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 207, 0)), 3478),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(74, 125, 250, 129)), 19302),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(142, 250, 82, 127)), 19302),
];

/// Classification of the NAT mapping behaviour observed on the QUIC socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunNatKind {
    /// Both STUN servers reported the exact same external `IP:port` —
    /// Endpoint-Independent Mapping (Cone NAT). Direct hole-punching works
    /// against this exact port.
    Cone,
    /// STUN servers reported the same IP but different ports (`delta` apart) —
    /// Symmetric CGNAT. Hole-punching requires a port fan around the base port.
    Symmetric { delta: i32 },
    /// Reflectors reported different public IPs; no stable endpoint is inferred.
    AddressDependent,
    /// Only one STUN server answered so far.
    SingleSample,
}

#[derive(Debug, Clone)]
pub struct StunMapping {
    pub external_addr: SocketAddr,
    pub local_port: u16,
    pub nat_kind: StunNatKind,
    /// RFC 5780 inbound filtering class — `Unknown` when the filtering
    /// probe never ran (refresh paths that skip it) or was inconclusive.
    pub filter: StunFilterKind,
}

static IPV4_LISTENER_SOCKET: RwLock<Option<RegisteredListenerSocket>> = RwLock::new(None);
static IPV6_LISTENER_SOCKET: RwLock<Option<RegisteredListenerSocket>> = RwLock::new(None);
static OBSERVED_MAPPING: RwLock<Option<(u64, StunMapping)>> = RwLock::new(None);
static NEXT_LISTENER_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Clone the active QUIC listener's underlying `UdpSocket` (for sending
/// keepalive pulses and hole-punch packets from the exact QUIC port).
pub fn clone_listener_udp_socket(ipv6: bool) -> Option<UdpSocket> {
    let lock = if ipv6 {
        &IPV6_LISTENER_SOCKET
    } else {
        &IPV4_LISTENER_SOCKET
    };
    lock.read()
        .ok()
        .and_then(|g| g.as_ref().and_then(|s| s.socket.try_clone().ok()))
}

/// Return the latest STUN-observed external mapping for the IPv4 QUIC listener.
pub fn observed_stun_mapping() -> Option<StunMapping> {
    let socket = IPV4_LISTENER_SOCKET.read().ok()?;
    let generation = socket.as_ref()?.generation;
    let mapping = OBSERVED_MAPPING.read().ok()?;
    mapping
        .as_ref()
        .filter(|(owner, _)| *owner == generation)
        .map(|(_, value)| value.clone())
}

/// Invalidate the observed mapping — called when the network changed
/// (interface death, VPN toggle): the stored external addr belonged to the
/// old interface and must not be re-announced while a fresh probe runs.
pub fn invalidate_observed_mapping() {
    if let Ok(mut observed) = OBSERVED_MAPPING.write() {
        *observed = None;
    }
}

/// Update the stored STUN mapping (called at socket bind and by refresh probes).
pub fn set_observed_stun_mapping(generation: u64, mapping: StunMapping) -> bool {
    let Ok(socket) = IPV4_LISTENER_SOCKET.read() else {
        return false;
    };
    let Some(socket) = socket.as_ref() else {
        return false;
    };
    if socket.generation != generation
        || socket.socket.local_addr().ok().map(|addr| addr.port()) != Some(mapping.local_port)
    {
        return false;
    }
    let Ok(mut observed) = OBSERVED_MAPPING.write() else {
        return false;
    };
    *observed = Some((generation, mapping));
    true
}

/// Build a 20-byte RFC 5389 STUN Binding Request with the given 12-byte tx_id.
pub fn build_binding_request(tx_id: [u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    // Message Type: 0x0001 (Binding Request), Message Length: 0x0000
    pkt[0] = 0x00;
    pkt[1] = 0x01;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    pkt[8..20].copy_from_slice(&tx_id);
    pkt
}

/// Parse an RFC 5389 STUN Binding Response and extract the mapped `SocketAddr`
/// (`XOR-MAPPED-ADDRESS` `0x0020` preferred, fallback `MAPPED-ADDRESS` `0x0001`).
pub fn parse_binding_response(buf: &[u8], expected_tx_id: Option<&[u8; 12]>) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    // Binding Success Response is 0x0101.
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return None;
    }
    if buf[4..8] != STUN_MAGIC_COOKIE {
        return None;
    }
    if let Some(tx) = expected_tx_id {
        if &buf[8..20] != tx {
            return None;
        }
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if msg_len % 4 != 0 || msg_len > buf.len() - 20 {
        return None;
    }
    let end = 20 + msg_len;
    let mut pos = 20;
    let mut fallback: Option<SocketAddr> = None;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > end {
            break;
        }
        let val = &buf[pos..pos + attr_len];
        // Attributes are padded to 4-byte boundaries.
        pos += (attr_len + 3) & !3;

        if attr_type == 0x0020 && val.len() >= 8 && val[1] == 0x01 {
            // XOR-MAPPED-ADDRESS (IPv4)
            let xport = u16::from_be_bytes([val[2], val[3]]);
            let port = xport ^ u16::from_be_bytes([STUN_MAGIC_COOKIE[0], STUN_MAGIC_COOKIE[1]]);
            let ip = Ipv4Addr::new(
                val[4] ^ STUN_MAGIC_COOKIE[0],
                val[5] ^ STUN_MAGIC_COOKIE[1],
                val[6] ^ STUN_MAGIC_COOKIE[2],
                val[7] ^ STUN_MAGIC_COOKIE[3],
            );
            return Some(SocketAddr::new(IpAddr::V4(ip), port));
        } else if attr_type == 0x0001 && val.len() >= 8 && val[1] == 0x01 {
            // MAPPED-ADDRESS (IPv4)
            let port = u16::from_be_bytes([val[2], val[3]]);
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            fallback = Some(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    fallback
}

/// Fast synchronous STUN probe on `socket` (used once before `quinn` wraps it).
/// Sends Binding Requests to all `PUBLIC_STUN_SERVERS` in parallel and collects
/// up to 2 responses within ~220 ms total.
pub fn probe_socket_sync(socket: &UdpSocket, local_port: u16) -> Option<StunMapping> {
    probe_with_reflectors(socket, local_port, PUBLIC_STUN_SERVERS)
}

/// Fire a 20-byte STUN Binding Request from the active QUIC listener socket
/// to all public STUN reflectors — keeps the NAT mapping alive (WireGuard
/// `PersistentKeepalive` equivalent).
pub fn send_keepalive_pulses() -> usize {
    if std::env::var_os("NOID_DISABLE_STUN").is_some() {
        return 0;
    }
    let Some(sock) = clone_listener_udp_socket(false) else {
        return 0;
    };
    let tx_id: [u8; 12] = rand::random();
    let req = build_binding_request(tx_id);
    let mut sent = 0;
    for srv in PUBLIC_STUN_SERVERS {
        if sock.send_to(&req, srv).is_ok() {
            sent += 1;
        }
    }
    sent
}
