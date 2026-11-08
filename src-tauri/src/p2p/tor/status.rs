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

/// Sanitized status snapshot. `onion_address` may exist while `state == Off`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TorStatus {
    pub desired_mode: TorMode,
    pub effective_mode: TorMode,
    pub generation: u64,
    pub state: TorState,
    pub bootstrap_percent: u8,
    pub service_published: bool,
    pub onion_address: Option<String>,
    pub relay_enabled: bool,
    pub relay_active: bool,
    /// Persisted metered-consent flag — the UI restores the toggle from it;
    /// `relay_active` stays the runtime gate (consent + running + opt-in).
    pub allow_metered_relay: bool,
    pub error_code: Option<String>,
}
