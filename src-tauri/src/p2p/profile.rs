//! Platform-adaptive node profile.
//!
//! The binary detects its platform once at `P2PNode::new` and applies a
//! behavior profile. The profile is a *policy* layer — it tunes strategy
//! order and budgets, never the protocol itself. Compile-time `cfg!` picks
//! the base profile; runtime signals (headless session, config override)
//! may refine it.
//!
//! | Profile  | When                        | Behavior deltas |
//! |----------|-----------------------------|-----------------|
//! | Mobile   | target_os = "android"       | QUIC-first (survives CGNAT rebinding), bounded punch-assist, relay role only when Public on unmetered net, single UPnP attempt |
//! | Desktop  | windows / linux GUI         | current behavior — TCP+WS+QUIC, UPnP, Auto role |
//! | Headless | linux w/o GUI or --headless | relay-candidate priority, verbose status logging |

use serde::{Deserialize, Serialize};

/// Which platform profile the node runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Mobile,
    Desktop,
    Headless,
}

/// Resolved behavior policy for this node.
#[derive(Debug, Clone)]
pub struct NodeProfile {
    pub kind: ProfileKind,
    /// Prefer QUIC when ranking outbound transports — QUIC connection IDs
    /// survive carrier NAT rebinds that kill TCP mappings mid-flow.
    pub prefer_quic: bool,
    /// Max simultaneous-open punch attempts per peer per minute.
    /// `0` disables punch-assist entirely (default on Desktop).
    pub punch_assist_per_min: u32,
    /// Attempt UPnP port mapping at all (mobile: one attempt, no retries).
    pub upnp_attempts: u32,
    /// Relay for others only on unmetered networks (mobile policy).
    pub unmetered_relay_only: bool,
}

impl NodeProfile {
    /// Detect the profile for this binary.
    ///
    /// Resolution order:
    /// 1. `NOID_PROFILE` env / config override (mobile|desktop|headless|auto)
    /// 2. `cfg!(target_os)` — android => Mobile, everything else => Desktop
    /// 3. Headless refinement on non-android: no `$DISPLAY` *and*
    ///    `--headless` arg or `NOID_HEADLESS` set => Headless
    pub fn detect(override_name: Option<&str>) -> Self {
        let forced = override_name
            .map(str::to_string)
            .or_else(|| std::env::var("NOID_PROFILE").ok())
            .map(|s| s.to_ascii_lowercase());

        let kind = match forced.as_deref() {
            Some("mobile") => ProfileKind::Mobile,
            Some("desktop") => ProfileKind::Desktop,
            Some("headless") => ProfileKind::Headless,
            _ => Self::auto_kind(),
        };
        Self::for_kind(kind)
    }

    #[cfg(target_os = "android")]
    fn auto_kind() -> ProfileKind {
        ProfileKind::Mobile
    }

    #[cfg(not(target_os = "android"))]
    fn auto_kind() -> ProfileKind {
        let headless_flag = std::env::args().any(|a| a == "--headless")
            || std::env::var("NOID_HEADLESS").is_ok();
        let no_display = std::env::var_os("DISPLAY").is_none()
            && std::env::var_os("WAYLAND_DISPLAY").is_none();
        if headless_flag && no_display {
            ProfileKind::Headless
        } else {
            ProfileKind::Desktop
        }
    }

    /// Policy table per profile kind.
    pub fn for_kind(kind: ProfileKind) -> Self {
        match kind {
            ProfileKind::Mobile => Self {
                kind,
                prefer_quic: true,
                punch_assist_per_min: 3,
                upnp_attempts: 1,
                unmetered_relay_only: true,
            },
            ProfileKind::Desktop => Self {
                kind,
                prefer_quic: false,
                punch_assist_per_min: 0,
                upnp_attempts: 5,
                unmetered_relay_only: false,
            },
            ProfileKind::Headless => Self {
                kind,
                prefer_quic: false,
                punch_assist_per_min: 0,
                upnp_attempts: 5,
                unmetered_relay_only: false,
            },
        }
    }

    /// Short name for logs and the `NodeProfile` event.
    pub fn name(&self) -> &'static str {
        match self.kind {
            ProfileKind::Mobile => "mobile",
            ProfileKind::Desktop => "desktop",
            ProfileKind::Headless => "headless",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_override_wins() {
        assert_eq!(
            NodeProfile::detect(Some("headless")).kind,
            ProfileKind::Headless
        );
        assert_eq!(
            NodeProfile::detect(Some("mobile")).kind,
            ProfileKind::Mobile
        );
    }

    #[test]
    fn mobile_policy_is_bounded() {
        let p = NodeProfile::for_kind(ProfileKind::Mobile);
        assert!(p.prefer_quic);
        assert!(p.punch_assist_per_min > 0 && p.punch_assist_per_min <= 5);
        assert!(p.unmetered_relay_only);
    }

    #[test]
    fn desktop_policy_matches_current_defaults() {
        let p = NodeProfile::for_kind(ProfileKind::Desktop);
        assert!(!p.prefer_quic);
        assert_eq!(p.punch_assist_per_min, 0);
        assert!(!p.unmetered_relay_only);
    }
}
