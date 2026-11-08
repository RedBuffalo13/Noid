//! Feature-agnostic Tor handle owned by `AppState`. Without `embedded-tor`
//! (or with `NOID_DISABLE_TOR=1`) every entry point reports `Unsupported`
//! rather than silently enabling anything.

use anyhow::{anyhow, Result};
use std::path::PathBuf;
use tokio::sync::watch;

use super::mode::TorMode;
use super::status::{TorState, TorStatus};

/// `NOID_DISABLE_TOR=1` forces every Tor path off — used by operators and
/// headless deployments that must guarantee no Tor code ever runs.
pub fn tor_disabled_by_env() -> bool {
    std::env::var_os("NOID_DISABLE_TOR").is_some_and(|v| v == "1")
}

/// Install the explicit rustls CryptoProvider. The dependency tree pulls
/// both `aws-lc-rs` and `ring`, and rustls 0.23 refuses to auto-pick —
/// without this every Tor TLS (guard) handshake panics the worker.
/// Idempotent; safe to call from multiple entry points.
#[cfg(feature = "embedded-tor")]
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Clone)]
pub struct TorHandle {
    status_rx: watch::Receiver<TorStatus>,
    /// Kept alive so the status channel never reports a closed stream; only
    /// written through the supervisor (or the env-disabled init above).
    #[allow(dead_code)]
    status_tx: watch::Sender<TorStatus>,
    #[cfg(feature = "embedded-tor")]
    supervisor: Option<std::sync::Arc<super::supervisor::TorSupervisor>>,
    #[allow(dead_code)]
    tor_dir: PathBuf,
}

impl TorHandle {
    pub fn new(tor_dir: PathBuf) -> Self {
        let (status_tx, status_rx) = watch::channel(TorStatus::default());
        #[cfg(feature = "embedded-tor")]
        let supervisor = if tor_disabled_by_env() {
            status_tx.send_modify(|s| s.state = TorState::Unsupported);
            None
        } else {
            Some(std::sync::Arc::new(super::supervisor::TorSupervisor::new(
                tor_dir.clone(),
                status_tx.clone(),
            )))
        };
        Self {
            status_rx,
            status_tx,
            #[cfg(feature = "embedded-tor")]
            supervisor,
            tor_dir,
        }
    }

    /// Base dir holding tor state (`tor_config.json`, keystore, arti dirs).
    pub fn dir(&self) -> &std::path::Path {
        &self.tor_dir
    }

    /// Whether embedded Tor exists in this build and is not env-disabled.
    pub fn supported(&self) -> bool {
        #[cfg(feature = "embedded-tor")]
        return self.supervisor.is_some() && !tor_disabled_by_env();
        #[cfg(not(feature = "embedded-tor"))]
        return false;
    }

    /// Status snapshot; `Unsupported` when the feature is absent/disabled.
    pub fn status(&self) -> TorStatus {
        if !self.supported() {
            let mut s = self.status_rx.borrow().clone();
            s.state = TorState::Unsupported;
            return s;
        }
        #[cfg(feature = "embedded-tor")]
        if let Some(sup_) = &self.supervisor {
            return sup_.status();
        }
        self.status_rx.borrow().clone()
    }

    /// Offline onion-identity ensure (PIN-gated master key). No Tor sockets.
    pub fn ensure_identity(&self, master: &[u8; 32]) -> Result<String> {
        #[cfg(feature = "embedded-tor")]
        if let Some(sup_) = &self.supervisor {
            return sup_.ensure_identity(master);
        }
        let _ = master;
        Err(anyhow!("embedded tor unsupported in this build"))
    }

    /// Live status watch — UI's `tor-status` event bridge and any
    /// subscriber that needs bootstrap/mode transitions without polling.
    pub fn status_watch(&self) -> watch::Receiver<TorStatus> {
        self.status_rx.clone()
    }

    /// Desired mode change; consent_version=0 is honored inside the
    /// supervisor (nothing Tor-side starts without consent).
    pub async fn set_desired(&self, mode: TorMode, consent_version: u32) -> Result<()> {
        #[cfg(feature = "embedded-tor")]
        if let Some(sup_) = &self.supervisor {
            return sup_.set_desired(mode, consent_version).await;
        }
        let _ = (mode, consent_version);
        Err(anyhow!("embedded tor unsupported in this build"))
    }

    /// Running TorClient `Arc` for the node's onion transport — `None` when
    /// no generation is up (unsupported/off/starting) or when built without
    /// `embedded-tor`.
    #[cfg(feature = "embedded-tor")]
    pub fn client(&self) -> Option<std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>> {
        self.supervisor.as_ref().and_then(|s| s.client())
    }

    /// Shared lazy client slot for `TorTransport` — resolved at dial time
    /// so the transport can be registered before bootstrap finishes.
    #[cfg(feature = "embedded-tor")]
    pub fn client_slot(
        &self,
    ) -> std::sync::Arc<
        std::sync::Mutex<Option<std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>>,
    > {
        self.supervisor
            .as_ref()
            .map(|s| s.client_slot())
            .unwrap_or_else(|| std::sync::Arc::new(std::sync::Mutex::new(None)))
    }

    /// Whether a Tor generation is currently running with a live client —
    /// `false` in builds without `embedded-tor`.
    pub fn running(&self) -> bool {
        #[cfg(feature = "embedded-tor")]
        return self.supervisor.as_ref().is_some_and(|s| s.client().is_some());
        #[cfg(not(feature = "embedded-tor"))]
        return false;
    }

    /// Feed accepted inbound onion streams into `tx` — the node calls this
    /// once per generation after constructing its `TorTransport`.
    #[cfg(feature = "embedded-tor")]
    pub fn wire_inbound(&self, tx: futures::channel::mpsc::Sender<arti_client::DataStream>) -> bool {
        self.supervisor.as_ref().is_some_and(|s| s.wire_inbound(tx))
    }

    /// P5: whether serving onion circuits is allowed right now — requires
    /// the persisted relay opt-in, consent, and a running generation.
    pub fn onion_relay_enabled(&self) -> bool {
        let cfg = super::config::load(&self.tor_dir.join("tor_config.json")).unwrap_or_default();
        cfg.onion_relay_enabled && cfg.consent_version > 0 && self.running()
    }

    /// Our `/onion3/<host>:4020` listen multiaddr — `None` without identity.
    pub fn listen_multiaddr(&self) -> Option<libp2p::Multiaddr> {
        let addr = self.status().onion_address?;
        let host = addr.strip_suffix(".onion").unwrap_or(&addr);
        format!("/onion3/{}:{}", host, super::onion_addr::ONION_VPORT).parse().ok()
    }

    /// Stop the running generation (bounded barrier inside the supervisor).
    pub async fn stop(&self) -> Result<()> {
        #[cfg(feature = "embedded-tor")]
        if let Some(sup_) = &self.supervisor {
            return sup_.stop().await;
        }
        Ok(())
    }
}
