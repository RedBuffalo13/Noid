//! SEC-1111-03: single gate for direct-network primitives — STUN, the
//! BitTorrent Mainline-DHT rendezvous, UDP hole-punch waves and
//! UPnP/NAT-PMP probes. All of them leak the real external IP (Mainline
//! DHT broadcasts it to arbitrary observers, STUN to Google/Cloudflare
//! servers), and every UDP path bypasses a configured TCP proxy entirely.
//!
//! Policy: direct networking is allowed ONLY when privacy is `Direct`, no
//! outbound proxy is active and Tor mode is not `TorOnly`. Everything else
//! fails closed — relayed/onion transports still work.

use crate::p2p::proxy_config::ProxyMode;
use crate::p2p::relay_config::PrivacyMode;
use crate::p2p::tor::mode::TorMode;

#[derive(Debug, Clone, Copy)]
pub struct DirectNetPolicy {
    pub privacy: PrivacyMode,
    pub proxy_active: bool,
    pub tor_mode: TorMode,
}

impl DirectNetPolicy {
    pub fn direct_allowed(&self) -> bool {
        self.privacy == PrivacyMode::Direct
            && !self.proxy_active
            && self.tor_mode != TorMode::TorOnly
    }
}

/// Fresh 128-bit rendezvous secret (hex) — one per generated invite.
pub fn fresh_rv_secret() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl crate::p2p::node::P2PNode {
    /// Live policy snapshot: privacy from the persisted relay config,
    /// proxy from `proxy_config.json`, Tor mode from the supervisor.
    pub(crate) fn direct_net_allowed(&self) -> bool {
        let proxy_active = crate::p2p::proxy_config::NoidProxyConfig::load_with_cipher(
            &self.data_dir,
            self.field_cipher.as_deref(),
        )
        .mode
            != ProxyMode::Off;
        let tor_mode = self
            .tor
            .as_ref()
            .map(|t| t.status().desired_mode)
            .unwrap_or(TorMode::Off);
        DirectNetPolicy {
            privacy: self.relay_config.privacy,
            proxy_active,
            tor_mode,
        }
        .direct_allowed()
    }
}
