//! Connectivity policy: persistent vs on-demand contact connections.
//!
//! Persisted as `connectivity_config.json` in the app data dir. When
//! `on_demand` is false the node behaves exactly like the legacy model —
//! contacts are auto-dialed at login and connections are kept alive
//! forever. When true, only infra connections (reserved relays, seeds,
//! active mailbox peers) stay up; contact conns die after an idle TTL
//! and are re-dialed on the next exchange.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-connection role in the swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnClass {
    /// Reserved relays, bootstrap seeds, active mailbox peers —
    /// never torn down by the idle policy.
    Infra,
    /// Ordinary contacts — eligible for idle teardown in on-demand mode.
    Contact,
}

/// Persisted connectivity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectivityConfig {
    /// false = legacy persistent model (default); true = on-demand.
    pub on_demand: bool,
    /// Seconds an idle contact connection lives in on-demand mode.
    pub idle_conn_ttl_secs: u64,
    /// Self-mailbox poll interval.
    pub mailbox_poll_secs: u64,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            on_demand: false,
            idle_conn_ttl_secs: 120,
            mailbox_poll_secs: 300,
        }
    }
}

impl ConnectivityConfig {
    /// Load `connectivity_config.json` from `config_dir`; fall back to
    /// defaults on missing/corrupt file (same quarantine policy as
    /// `RelayConfig::load`).
    pub fn load(config_dir: &Path) -> Self {
        let path = config_dir.join("connectivity_config.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Self>(&content) {
                Ok(cfg) => {
                    log::debug!(
                        "Loaded connectivity config: on_demand={}, idle_ttl={}s, poll={}s",
                        cfg.on_demand,
                        cfg.idle_conn_ttl_secs,
                        cfg.mailbox_poll_secs
                    );
                    cfg
                }
                Err(e) => {
                    log::warn!("Invalid connectivity_config.json ({}), using defaults", e);
                    let _ = crate::util::quarantine::quarantine(&path);
                    let cfg = Self::default();
                    if let Err(se) = cfg.save(config_dir) {
                        log::warn!("Failed to write default connectivity_config: {}", se);
                    }
                    cfg
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Persist the config atomically (tmp + rename — a crash mid-write
    /// must not leave a half-written JSON).
    pub fn save(&self, config_dir: &Path) -> std::io::Result<()> {
        let path = config_dir.join("connectivity_config.json");
        let tmp = config_dir.join("connectivity_config.json.tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_legacy_persistent() {
        let c = ConnectivityConfig::default();
        assert!(!c.on_demand);
        assert_eq!(c.idle_conn_ttl_secs, 120);
        assert_eq!(c.mailbox_poll_secs, 300);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("noid-cc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = ConnectivityConfig {
            on_demand: true,
            idle_conn_ttl_secs: 60,
            mailbox_poll_secs: 240,
        };
        c.save(&dir).unwrap();
        let loaded = ConnectivityConfig::load(&dir);
        assert_eq!(loaded.on_demand, true);
        assert_eq!(loaded.idle_conn_ttl_secs, 60);
        assert_eq!(loaded.mailbox_poll_secs, 240);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let dir = std::env::temp_dir().join("noid-cc-missing-dir");
        let loaded = ConnectivityConfig::load(&dir);
        assert!(!loaded.on_demand);
    }
}
