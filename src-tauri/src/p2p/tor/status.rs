//! Tor runtime status reported to UI; never carries secrets or raw endpoints.
use serde::{Deserialize, Serialize};
use super::mode::TorMode;

/// Coarse lifecycle state; `unsupported` covers builds without the feature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorState {
    #[default]
    Off,
    Starting,
    Bootstrapping,
    Publishing,
    Ready,
    Degraded,
    Stopping,
    Failed,
    Unsupported,
}

/// RV-05: onion service publication — `is_fully_reachable` only proves the
/// introduction points are up; the HSDir descriptor may still be missing
/// (observed: upload timeouts with reachable intros). `Published` requires
/// a successful self-connect probe — a real descriptor fetch + intro +
/// rendezvous + accept, the exact path an inviter walks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishState {
    /// Service down or intro points not established.
    #[default]
    Unpublished,
    /// Intro points reachable but no end-to-end proof yet.
    Publishing,
    /// Self-probe succeeded within the freshness window — the descriptor
    /// is fetchable and the service accepts rendezvous.
    Published,
}

/// Sanitized status snapshot. `onion_address` may exist while `state == Off`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TorStatus {
    pub desired_mode: TorMode,
    pub effective_mode: TorMode,
    pub generation: u64,
    pub state: TorState,
    pub bootstrap_percent: u8,
    pub service_published: bool,
    /// RV-05: verified publication tier — invite/endpoint-advertise must
    /// gate onion hints on `Published`, not on `service_published`.
    #[serde(default)]
    pub publish_state: PublishState,
    pub onion_address: Option<String>,
    pub relay_enabled: bool,
    pub relay_active: bool,
    /// Persisted metered-consent flag — the UI restores the toggle from it;
    /// `relay_active` stays the runtime gate (consent + running + opt-in).
    pub allow_metered_relay: bool,
    pub error_code: Option<String>,
}
