use super::{build_binding_request, classify_stun_samples, parse_binding_response, StunMapping};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Probe an explicit reflector set, allowing isolated loopback regressions.
pub(crate) fn probe_with_reflectors(
    socket: &UdpSocket,
    local_port: u16,
    servers: &[SocketAddr],
) -> Option<StunMapping> {
    let bound_port = socket.local_addr().ok()?.port();
    if local_port != 0 && local_port != bound_port {
        return None;
    }
    socket.set_nonblocking(false).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(180)))
        .ok()?;
    socket
        .set_write_timeout(Some(Duration::from_millis(100)))
        .ok()?;

    let tx_id: [u8; 12] = rand::random();
    let req = build_binding_request(tx_id);
    for srv in servers {
        let _ = socket.send_to(&req, srv);
    }

    let mut samples = Vec::new();
    let mut buf = [0u8; 256];
    for _ in 0..servers.len() {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if !servers.contains(&from) {
                    continue;
                }
                if let Some(mapped) = parse_binding_response(&buf[..n], Some(&tx_id)) {
                    if !samples.iter().any(|(s, _)| *s == from) {
                        samples.push((from, mapped));
                    }
                    if samples.len() >= 2 {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let _ = socket.set_read_timeout(None);
    let _ = socket.set_write_timeout(None);
    let (external_addr, nat_kind) = classify_stun_samples(&samples)?;
    // RFC 5780 filtering probe on the first reflector that answered —
    // a mapping alone is a claim; the filter class decides whether an
    // unsolicited packet from a cold peer actually gets in.
    let filter = samples
        .first()
        .map(|(srv, _)| super::probe_filtering(socket, *srv))
        .unwrap_or(super::StunFilterKind::Unknown);
    Some(StunMapping {
        external_addr,
        local_port: bound_port,
        nat_kind,
        filter,
    })
}
