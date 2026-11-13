use libp2p::{Multiaddr, PeerId};

use crate::p2p::addr_class::AddrClass;
use crate::p2p::classify_peer_addr::classify_peer_addr;

/// Whether `addr` may enter the persistent peer cache / Kademlia address
/// book for `target`. `Local` and `Malformed` addrs can never reach a remote
/// peer — persisting them produces immortal redial loops on every startup.
/// `Lan` addrs are kept: they are the only path on LAN-only networks, and
/// the cache sorts them behind public addrs anyway. `Onion3` is kept: it is
/// a WAN-routable hint via the Tor transport — dropping it meant onion
/// connectivity silently vanished on every restart (register_peer_addr's
/// contract is "local dial book + peer cache").
pub fn is_wan_cacheable(addr: &Multiaddr, target: &PeerId) -> bool {
    matches!(
        classify_peer_addr(addr, target),
        AddrClass::PublicDirect | AddrClass::Lan | AddrClass::Circuit | AddrClass::Onion3
    )
}
