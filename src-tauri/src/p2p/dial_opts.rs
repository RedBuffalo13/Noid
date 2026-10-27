use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{Multiaddr, PeerId};

/// Build [`DialOpts`] for dialing `addr`, bound to `peer` when known.
///
/// `DialOpts` defaults to `PortUse::Reuse`, which makes libp2p-tcp bind the
/// outbound socket to our own listen port. On Windows — where SO_REUSEPORT
/// does not exist — that bind fails with WSAEADDRINUSE (os error 10048)
/// whenever the port is already held by our listener or an established
/// reuse-connection, so every explicit dial allocates a fresh port there.
/// Unix keeps `PortUse::Reuse`: DCUtR hole punching needs both peers on
/// stable, reused ports.
///
/// Binding the dial to the peer id additionally gives `OutgoingConnectionError`
/// a `Some(peer_id)` so failure handling can evict the dead addr and arm
/// backoff — bare-addr dials previously produced `peer_id: None` and were
/// retried forever.
pub fn dial_opts(peer: Option<PeerId>, addr: Multiaddr) -> DialOpts {
    match peer {
        Some(peer) => {
            // A misattributed hint (e.g. a bare relay addr that leaked into
            // a peer's book) must not raise "Unexpected peer ID" — dial the
            // addr's own terminal id instead of the caller's expectation.
            let effective = crate::p2p::terminal_peer_id::terminal_peer_id(&addr)
                .unwrap_or(peer);
            let opts = DialOpts::peer_id(effective).addresses(vec![addr]);
            #[cfg(windows)]
            let opts = opts.allocate_new_port();
            opts.build()
        }
        None => {
            let opts = DialOpts::unknown_peer_id().address(addr);
            #[cfg(windows)]
            let opts = opts.allocate_new_port();
            opts.build()
        }
    }
}

/// Build [`DialOpts`] for dialing several `addrs` toward `peer` while a
/// connection to it may already exist.
///
/// `DialOpts::peer_id` defaults to `PeerCondition::DisconnectedAndNotDialing`
/// — the swarm rejects the dial outright while ANY conn to the peer is up.
/// That silently kills every direct-upgrade attempt over an open
/// `/p2p-circuit` conn (TR-02): the upgrade is exactly what must run while
/// the circuit is still live. `PeerCondition::NotDialing` refuses only a
/// duplicate in-flight dial and lets the upgrade proceed. Multiple addrs
/// let the swarm fall through to the next transport (QUIC → TCP → WS)
/// when the preferred one is dead.
pub fn dial_opts_multi(peer: PeerId, addrs: Vec<Multiaddr>) -> DialOpts {
    // Drop addrs whose terminal /p2p/ id does not match `peer` — a bare relay
    // addr (`…/tcp/4020/p2p/<relay>`) that leaked into the peer's book yields
    // "Unexpected peer ID" at dial time instead of a useful connection.
    let addrs: Vec<Multiaddr> = addrs
        .into_iter()
        .filter(|a| {
            crate::p2p::terminal_peer_id::terminal_peer_id(a)
                .map(|id| id == peer)
                .unwrap_or(true)
        })
        .collect();
    let opts = DialOpts::peer_id(peer)
        .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
        .addresses(addrs);
    #[cfg(windows)]
    let opts = opts.allocate_new_port();
    opts.build()
}
