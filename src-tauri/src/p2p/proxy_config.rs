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
        Self::load_with_cipher(data_dir, None)
    }

    /// Load with a field cipher — `NOIDF2` ciphertexts decrypt, legacy
    /// plaintext JSON still parses (resaved encrypted on next save).
    /// Without a cipher an encrypted file fails closed → `Off`... no:
    /// failing closed means "proxy silently off" — for a censor-evading
    /// proxy that is the LEAK. Encrypted-but-undecryptable config must
    /// not dial direct; callers must pass the cipher once unlocked.
    pub fn load_with_cipher(
        data_dir: &Path,
        cipher: Option<&crate::security::field_cipher::FieldCipher>,
    ) -> Self {
        let path = data_dir.join("proxy_config.json");
        let Ok(raw) = std::fs::read(&path) else {
            return Self::default();
        };
        if raw.starts_with(b"NOIDF2") {
            return match cipher.and_then(|c| c.decrypt_bytes(&raw).ok()) {
                Some(pt) => serde_json::from_slice(&pt).unwrap_or_default(),
                // Cipher present but decrypt failed (tampered/wrong key) or
                // cipher absent → fail-closed: refuse direct dials entirely
                // by reporting an unresolvable proxy so nothing leaks.
                None => Self {
                    mode: ProxyMode::Socks5,
                    host: "127.0.0.1:1".into(),
                    username: None,
                    password: None,
                },
            };
        }
        serde_json::from_slice(&raw).unwrap_or_else(|e| {
            log::warn!("Invalid proxy_config.json ({}), proxy disabled", e);
            Self::default()
        })
    }

    /// Persist to `data_dir/proxy_config.json`.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        let path = data_dir.join("proxy_config.json");
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, raw).map_err(|e| e.to_string())
    }

    /// Persist encrypted (NOIDF2) when a cipher is available; plaintext
    /// fallback only when no master key exists yet (pre-unlock).
    pub fn save_with_cipher(
        &self,
        data_dir: &Path,
        cipher: Option<&crate::security::field_cipher::FieldCipher>,
    ) -> Result<(), String> {
        let path = data_dir.join("proxy_config.json");
        let raw = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let out = match cipher {
            Some(c) => c.encrypt_bytes(&raw).map_err(|e| e.to_string())?,
            None => raw,
        };
        std::fs::write(&path, out).map_err(|e| e.to_string())
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
