//! Runtime relay/NAT status exposed to the frontend.

use serde::{Deserialize, Serialize};

/// Public reachability of this node as measured by AutoNAT / UPnP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatStatus {
    /// Not yet determined.
    #[default]
    Unknown,
    /// We have a confirmed public external address.
    Public,
    /// Behind NAT without port mapping — reachable only via relays.
    Private,
}

/// Snapshot of this node's relay participation for the UI.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatus {
    pub nat_status: NatStatus,
    /// Whether we currently accept reservations from other peers.
    pub is_relaying: bool,
    /// Confirmed public external addresses (empty when behind NAT).
    pub external_addrs: Vec<String>,
    /// Our own `/p2p-circuit` addresses obtained via relay reservations.
    pub relayed_addrs: Vec<String>,
    /// Reservations we hold on remote relays.
    pub active_reservations: usize,
    /// Reservations other peers currently hold on us.
    pub inbound_reservations: usize,
    /// Relay circuits currently passing through us.
    pub active_circuits: usize,
    /// Relay peers we know about (bootstrap + DHT-discovered).
    pub known_relays: usize,
    /// Peers we are currently connected to — grows as circles merge.
    pub peers_connected: usize,
    /// External QUIC address maintained by 20s STUN PersistentKeepalive.
    #[serde(default)]
    pub stun_addr: Option<String>,
    /// Detailed NAT mapping mode: `"public_port_mapped"` | `"stun_cone"` |
    /// `"stun_symmetric"` | `"stun_mapped"` | `"unknown"`.
    #[serde(default)]
    pub nat_mapping: String,
    /// RV-03: the AutoNAT probe window (60s from the first conn/candidate)
    /// expired while status stayed `Unknown` — the UI should stop showing
    /// "Detecting…" and report honest "unreachable inbound".
    #[serde(default)]
    pub probe_exhausted: bool,
    /// RV-04: fresh per-addr evidence snapshot (canonical addr → state) —
    /// the invite builder ranks hints by it; the UI may badge verified
    /// addrs later.
    #[serde(default)]
    pub addr_evidence: std::collections::HashMap<String, crate::p2p::addr_evidence::EvidenceState>,
}
