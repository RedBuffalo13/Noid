use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

/// The peer an address ultimately targets: the TERMINAL `/p2p/` id.
///
/// For a circuit address `…/p2p/<relay>/p2p-circuit/p2p/<target>` the first
/// `/p2p/` id is the relay hop — registering the address under it is dropped
/// as malformed by `classify_peer_addr` (the terminal id does not match),
/// so the actual target never gets a dialable address. This bug killed the
/// invite flow on circuit-only invites.
pub fn terminal_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter()
        .filter_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_addr_yields_its_peer() {
        let p = PeerId::random();
        let a: Multiaddr = format!("/ip4/8.8.8.8/tcp/4001/p2p/{p}").parse().unwrap();
        assert_eq!(terminal_peer_id(&a), Some(p));
    }

    #[test]
    fn circuit_addr_yields_target_not_relay() {
        let relay = PeerId::random();
        let target = PeerId::random();
        let a: Multiaddr = format!(
            "/ip4/8.8.8.8/tcp/4010/p2p/{relay}/p2p-circuit/p2p/{target}"
        )
        .parse()
        .unwrap();
        assert_eq!(terminal_peer_id(&a), Some(target));
    }

    #[test]
    fn ws_circuit_addr_yields_target() {
        let relay = PeerId::random();
        let target = PeerId::random();
        let a: Multiaddr = format!(
            "/ip4/8.8.8.8/tcp/4011/ws/p2p/{relay}/p2p-circuit/p2p/{target}"
        )
        .parse()
        .unwrap();
        assert_eq!(terminal_peer_id(&a), Some(target));
    }

    #[test]
    fn no_p2p_yields_none() {
        let a: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        assert_eq!(terminal_peer_id(&a), None);
    }
}
