use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

/// Dial preference for a transport address — lower is tried first.
///
/// QUIC first: UDP flows survive carrier NAT rebinding via connection
/// migration (observed Tele2 evicting mid-flow mappings on TCP). Plain TCP
/// next, WebSocket last — the extra framing adds latency without buying
/// reachability the plain transports lack.
pub fn transport_rank(addr: &Multiaddr) -> u8 {
    let mut rank = 3;
    for p in addr.iter() {
        match p {
            Protocol::QuicV1 => rank = 0,
            Protocol::Ws(_) | Protocol::Wss(_) => rank = rank.min(2),
            Protocol::Tcp(_) => rank = rank.min(1),
            _ => {}
        }
    }
    rank
}
