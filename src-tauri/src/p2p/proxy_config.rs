//! Outbound proxy configuration (`proxy_config.json` in the app data dir).
//!
//! When `mode != off`, all TCP/WS dials are tunneled through the proxy
//! (HTTP CONNECT or SOCKS5) via the vendored libp2p-tcp transport.
//! QUIC is unaffected. The proxy never makes the node reachable — it is
//! outbound-only censorship/NAT traversal.

use libp2p_tcp::proxy::ProxyConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Proxy mode persisted in the config file.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Direct dials — stock behaviour (default).
    #[default]
    Off,
    /// HTTP CONNECT tunnel.
    Http,
    /// SOCKS5 (no-auth or user/pass).
    Socks5,
}

/// On-disk proxy configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NoidProxyConfig {
    pub mode: ProxyMode,
    /// `host:port` of the proxy server.
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl NoidProxyConfig {
    /// Load from `data_dir/proxy_config.json`; missing/invalid → Off.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("proxy_config.json");
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                log::warn!("Invalid proxy_config.json ({}), proxy disabled", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Persist to `data_dir/proxy_config.json`.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        let path = data_dir.join("proxy_config.json");
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, raw).map_err(|e| e.to_string())
    }

    /// Resolve into the transport-level config; `None` when Off or the
    /// host fails to parse as `ip:port` (noid only dials IP literals).
    pub fn to_transport(&self) -> Option<ProxyConfig> {
        if self.mode == ProxyMode::Off {
            return None;
        }
        let addr: SocketAddr = self.host.trim().parse().ok()?;
        let base = match self.mode {
            ProxyMode::Http => ProxyConfig::http(addr),
            ProxyMode::Socks5 => {
                ProxyConfig::socks5(addr, self.username.clone(), self.password.clone())
            }
            ProxyMode::Off => unreachable!(),
        };
        Some(match (self.mode, &self.username, &self.password) {
            (ProxyMode::Http, Some(u), Some(p)) => base.with_auth(u.clone(), p.clone()),
            _ => base,
        })
    }

    /// Apply this config to the running transport.
    pub fn apply(&self) {
        libp2p_tcp::proxy::set_proxy(self.to_transport());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_yields_no_transport() {
        assert!(NoidProxyConfig::default().to_transport().is_none());
    }

    #[test]
    fn socks5_maps_fields() {
        let c = NoidProxyConfig {
            mode: ProxyMode::Socks5,
            host: "127.0.0.1:9050".into(),
            username: Some("u".into()),
            password: Some("p".into()),
        };
        let t = c.to_transport().unwrap();
        assert_eq!(t.kind, libp2p_tcp::proxy::ProxyKind::Socks5);
        assert_eq!(t.addr.port(), 9050);
    }

    #[test]
    fn bad_host_falls_back_to_direct() {
        let c = NoidProxyConfig {
            mode: ProxyMode::Http,
            host: "not-an-addr".into(),
            ..Default::default()
        };
        assert!(c.to_transport().is_none());
    }
}
