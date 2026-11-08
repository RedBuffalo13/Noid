//! Tor connectivity mode selected by the user.
use serde::{Deserialize, Serialize};

/// Tor is always off by default; `tor_only` never falls back to direct I/O.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorMode {
    /// No Tor client or onion service; ordinary networking only.
    #[default]
    Off,
    /// Onion connectivity in addition to ordinary networking (consent-gated).
    Additional,
    /// Onion-only policy; unknown onion paths wait or error, never fall back.
    TorOnly,
}

/// Returns true when LAN/mDNS/direct discovery transports may be constructed.
pub fn direct_networking_allowed(mode: TorMode) -> bool {
    !matches!(mode, TorMode::TorOnly)
}
