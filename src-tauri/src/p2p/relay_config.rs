//! Relay configuration: node role, privacy mode, circuit relay v2 limits.
//!
//! Every noid node carries the relay server behaviour. Whether it actually
//! relays traffic for other peers is decided by [`NodeRole`] combined with
//! the AutoNAT-measured public reachability at runtime.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// How this node participates in relaying traffic for other peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Relay only when AutoNAT confirms public reachability.
    Auto,
    /// Always try to relay (fixed listen port + UPnP port mapping).
    Relay,
    /// Never relay other peers' traffic.
    Client,
}

/// How our own IP address is exposed to peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Direct connections allowed — connected peers can observe our IP.
    Direct,
    /// Only circuit-relayed communication — peers see the relay's IP, not ours.
    /// We do not advertise direct/external addresses and only dial via
    /// `/p2p-circuit` addresses.
    RelayedOnly,
}

/// Persisted relay configuration (`relay_config.json` in the app data dir).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    pub role: NodeRole,
    pub privacy: PrivacyMode,
    /// Fixed TCP/WS listen port used when relaying. `0` = ephemeral.
    /// A fixed port is required for UPnP mappings to stay stable.
    /// Defaults to the canonical relay port 4020 (WS on +1) — matches the
    /// bundled bootstrap seed in `resources/bootstrap_nodes.json`.
    pub listen_port: u16,
    /// Public multiaddr this node advertises (e.g. `/ip4/1.2.3.4/tcp/4010`).
    /// Needed on VPS relays before AutoNAT has any observer to confirm with.
    pub external_addr: Option<String>,
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration_secs: u64,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration_secs: u64,
    pub max_circuit_bytes: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        // Mirrors libp2p-relay 0.18 conservative defaults.
        Self {
            role: NodeRole::Auto,
            privacy: PrivacyMode::Direct,
            listen_port: 4020,
            external_addr: None,
            max_reservations: 128,
            max_reservations_per_peer: 4,
            reservation_duration_secs: 3600,
            // Circuit caps must absorb churn bursts: a client fighting CGNAT
            // re-dials a circuit per retry while zombie circuits linger until
            // their carrier conn is reaped (~36s). 64/8 was observed denying
            // legit requests in waves — 256/16 keeps abuse bounded (each
            // circuit is still byte-capped) without starving recovery.
            max_circuits: 256,
            max_circuits_per_peer: 16,
            // libp2p's 120s/128KiB circuit caps kill every relayed session
            // mid-conversation — on CGNAT clients the circuit IS the
            // connection. A circuit must outlive the 1h reservation it
            // rides: 24h covers a full offline-delivery day and 512 MiB
            // carries real backlog volumes without mid-session truncation.
            max_circuit_duration_secs: 86_400,
            max_circuit_bytes: 1 << 29, // 512 MiB per circuit
        }
    }
}

impl RelayConfig {
    /// Build the libp2p relay server config from our settings.
    /// `Client` role zeroes all limits so every reservation/circuit request
    /// is denied at the protocol level.
    pub fn to_libp2p_config(&self) -> libp2p::relay::Config {
        use crate::p2p::relay_rate_limit;
        let mut cfg = libp2p::relay::Config {
            max_reservations: self.max_reservations,
            max_reservations_per_peer: self.max_reservations_per_peer,
            reservation_duration: Duration::from_secs(self.reservation_duration_secs),
            // Floor, not the raw value: config files written before the
            // capacity bump (64/8) keep starving churning clients — clamp so
            // existing installs inherit the fix.
            max_circuits: self.max_circuits.max(256),
            max_circuits_per_peer: self.max_circuits_per_peer.max(16),
            // Floors, not raw values: configs written before the circuit
            // capacity bump keep truncating relayed sessions at 1h/64MiB —
            // clamp so existing installs inherit the fix.
            max_circuit_duration: Duration::from_secs(
                self.max_circuit_duration_secs.max(86_400),
            ),
            max_circuit_bytes: self.max_circuit_bytes.max(1 << 29),
            // libp2p's token buckets (30/hr per peer, 60/hr per IP) starve a
            // client that re-dials circuits during conn-flap recovery — the
            // observed "(limits)" denial waves. Sized for a small private
            // network: concurrent caps above still bound real abuse.
            reservation_rate_limiters: vec![
                relay_rate_limit::per_peer(120, Duration::from_secs(30)),
                relay_rate_limit::per_ip(240, Duration::from_secs(15)),
            ],
            circuit_src_rate_limiters: vec![
                relay_rate_limit::per_peer(240, Duration::from_secs(15)),
                relay_rate_limit::per_ip(480, Duration::from_secs(7)),
            ],
        };
        if self.role == NodeRole::Client {
            cfg.max_reservations = 0;
            cfg.max_reservations_per_peer = 0;
            cfg.max_circuits = 0;
            cfg.max_circuits_per_peer = 0;
        }
        cfg
    }

    /// Load `relay_config.json` from `config_dir`; fall back to defaults.
    pub fn load(config_dir: &Path) -> Self {
        let path = config_dir.join("relay_config.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Self>(&content) {
                Ok(cfg) => {
                    log::debug!(
                        "Loaded relay config: role={:?}, privacy={:?}, port={}",
                        cfg.role,
                        cfg.privacy,
                        cfg.listen_port
                    );
                    cfg
                }
                Err(e) => {
                    log::warn!("Invalid relay_config.json ({}), using defaults", e);
                    // Keep the broken file as *.corrupt-* and write fresh
                    // defaults so the next start is clean too.
                    let _ = crate::util::quarantine::quarantine(&path);
                    let cfg = Self::default();
                    if let Err(se) = cfg.save(config_dir) {
                        log::warn!("Failed to rewrite relay_config.json: {}", se);
                    }
                    cfg
                }
            },
            Err(_) => {
                let cfg = Self::default();
                if let Err(e) = cfg.save(config_dir) {
                    log::warn!("Failed to write default relay_config.json: {}", e);
                }
                cfg
            }
        }
    }

    /// Persist the configuration to `relay_config.json`.
    pub fn save(&self, config_dir: &Path) -> anyhow::Result<()> {
        let path = config_dir.join("relay_config.json");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}
