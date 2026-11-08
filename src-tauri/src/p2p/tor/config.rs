//! Persisted Tor configuration. Stores consent + flags only — no key material.
use serde::{Deserialize, Serialize};
use super::mode::TorMode;

pub const TOR_CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TorConfig {
    pub schema_version: u32,
    pub mode: TorMode,
    /// Version of the consent text the user accepted; 0 = never consented.
    pub consent_version: u32,
    pub onion_relay_enabled: bool,
    pub allow_metered_relay: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            schema_version: TOR_CONFIG_SCHEMA_VERSION,
            mode: TorMode::Off,
            consent_version: 0,
            onion_relay_enabled: false,
            allow_metered_relay: false,
        }
    }
}

impl TorConfig {
    /// Atomic write (tmp + rename). The file carries consent + flags only —
    /// no key material — so it stays a plain JSON document.
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Load persisted config; missing file means defaults (mode off). A config
/// from a newer schema is rejected rather than silently downgraded.
pub fn load(path: &std::path::Path) -> anyhow::Result<TorConfig> {
    if !path.exists() {
        return Ok(TorConfig::default());
    }
    let data = std::fs::read(path)?;
    let cfg: TorConfig = serde_json::from_slice(&data)?;
    anyhow::ensure!(
        cfg.schema_version <= TOR_CONFIG_SCHEMA_VERSION,
        "tor config schema {} newer than supported {}",
        cfg.schema_version,
        TOR_CONFIG_SCHEMA_VERSION
    );
    Ok(cfg)
}
