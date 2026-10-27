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
}
