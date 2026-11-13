//! RFC 5780 NAT *filtering* probe — the second half of reachability that
//! the mapping probe cannot see: even with an Endpoint-Independent
//! *mapping* (Cone), inbound packets may still be filtered by source.
//! Cold-dialability needs BOTH: EIM mapping + endpoint-independent
//! filtering.
//!
//! Runs RFC 5780 §4.5 Test II/III against ONE reflector that already
//! answered the mapping probe: CHANGE-REQUEST asks the server to reply
//! from a different IP+port (Test II) and then from the same IP with a
//! different port (Test III). The response arrives from an address we
//! never contacted — if it gets in, our filtering is loose.
//!
//! Conservative by construction: an RFC-3489-only server answers neither
//! test, which reads as `PortDependent` — the pessimistic class. Failing
//! toward pessimism is safe: it lowers a candidate's rank instead of
//! raising a phantom one. Runs once per bind/network-change, never on
//! the 20s keepalive tick (battery).

use super::{build_binding_request, parse_binding_response};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// RFC 5780 filtering classification of the NAT in front of our socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunFilterKind {
    /// A response from an unrelated endpoint got in — the mapping accepts
    /// packets from ANY external IP:port. This is the cold-dialable case.
    EndpointIndependent,
    /// Packets from an already-contacted IP get in on any port — punch
    /// works after we ping the target once.
    AddressDependent,
    /// Only the exact contacted IP:port gets through — hole-punching
    /// needs synchronized timing.
    PortDependent,
    /// Probe inconclusive (reflectors lost, all unsupported).
    Unknown,
}

/// CHANGE-REQUEST (RFC 5780 §7.2): 4-byte value; bit 0x04 asks for a
/// different source IP, bit 0x02 for a different source port.
fn build_change_request(tx_id: [u8; 12], change_ip: bool, change_port: bool) -> [u8; 28] {
    let mut pkt = [0u8; 28];
    pkt[..20].copy_from_slice(&build_binding_request(tx_id));
    pkt[2] = 0x00;
    pkt[3] = 0x08; // message length = attr header(4) + value(4)
    pkt[20] = 0x00;
    pkt[21] = 0x03; // CHANGE-REQUEST
    pkt[22] = 0x00;
    pkt[23] = 0x04; // attr length
    let mut flags = 0u8;
    if change_ip {
        flags |= 0x04;
    }
    if change_port {
        flags |= 0x02;
    }
    pkt[27] = flags; // flags live in the value's low byte
    pkt
}

/// One change-request round-trip: any response (from WHATEVER source —
/// Test II replies come from the server's *other* address) with our
/// tx_id proves the packet got through the filter.
fn try_change(socket: &UdpSocket, server: SocketAddr, change_ip: bool, change_port: bool) -> bool {
    let tx_id: [u8; 12] = rand::random();
    let req = build_change_request(tx_id, change_ip, change_port);
    if socket.send_to(&req, server).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    // Two short reads — the response may share the queue with stray
    // QUIC datagrams on the listener socket; tx_id filters them out.
    for _ in 0..3 {
        match socket.recv_from(&mut buf) {
            Ok((n, _from)) => {
                if parse_binding_response(&buf[..n], Some(&tx_id)).is_some() {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

/// Classify NAT filtering via one cooperative reflector. `server` should
/// be one that already answered the mapping probe — the baseline round
/// trip is known-good, so silence here means filtering (or no RFC 5780
/// support → pessimistic `PortDependent`).
pub(crate) fn probe_filtering(socket: &UdpSocket, server: SocketAddr) -> StunFilterKind {
    if socket.set_nonblocking(false).is_err()
        || socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .is_err()
    {
        return StunFilterKind::Unknown;
    }
    let kind = if try_change(socket, server, true, true) {
        StunFilterKind::EndpointIndependent
    } else if try_change(socket, server, false, true) {
        StunFilterKind::AddressDependent
    } else {
        StunFilterKind::PortDependent
    };
    let _ = socket.set_read_timeout(None);
    kind
}
