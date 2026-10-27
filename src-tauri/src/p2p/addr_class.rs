/// Reachability/validity class of a peer multiaddr — the single taxonomy
/// every address-ingestion point (peer cache, Kademlia, bootstrap, Identify)
/// must agree on so stale or undialable addrs cannot enter the address book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    /// Public IP/DNS transport dialing the peer directly.
    PublicDirect,
    /// Private/LAN/CGNAT/link-local transport — usable only for same-LAN
    /// peers; kept as a fallback but dialed last.
    Lan,
    /// Loopback or unspecified IP — only ever reaches the local host, never
    /// a remote peer.
    Local,
    /// Exactly one `/p2p-circuit` over a public relay prefix, terminating at
    /// the expected peer.
    Circuit,
    /// Structurally invalid for this peer: nested circuits, a circuit or
    /// addr terminating at a different peer id, `/tcp/0`, missing transport,
    /// or a circuit via a loopback/unspecified relay prefix.
    Malformed,
}
