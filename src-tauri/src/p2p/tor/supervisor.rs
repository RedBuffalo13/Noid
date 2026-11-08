//! Generation-owned Tor client/service lifecycle.
//!
//! One `TorSupervisor` owns at most one running generation (client + optional
//! onion service + monitor task). A mode change tears the old generation down
//! through a bounded barrier — drop of `TorClient` provably closes its
//! streams (~0.08s, probe-measured) — before a new generation is built, so a
//! stale generation can never write into a re-logged/re-moded session.
//!
//! Nothing here opens a Tor socket until consent exists (`TorConfig.
//! consent_version > 0`); `ensure_identity` is offline keystore work only.
//! The vendored arti-client patch surfaces fatal protocol recommendations via
//! `protocol_fatal_reason()` instead of exiting the process — the monitor and
//! every `status()` call translate it into `TorState::Failed` + teardown.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::StreamExt;
use tor_rtcompat::PreferredRuntime;

use super::identity::{ensure_onion_identity, OnionIdentity};
use super::mode::TorMode;
use super::status::{TorState, TorStatus};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_BARRIER: Duration = Duration::from_secs(5);

/// One running Tor generation: client + optional service + owned tasks.
struct Running {
    client: Arc<TorClient<PreferredRuntime>>,
    /// Held so the service keeps publishing; dropped to stop it.
    service: Option<Arc<tor_hsservice::RunningOnionService>>,
    /// Inbound rendezvous stream — P2 wires it into the node transport.
    /// Held (not polled) so descriptors keep accepting intro requests.
    rend: Option<std::pin::Pin<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send>>>,
    monitor: tokio::task::JoinHandle<()>,
    /// Accept loop draining rend -> transport channel (spawned by
    /// `wire_inbound` once the node's TorTransport exists).
    accept: Option<tokio::task::JoinHandle<()>>,
}

struct Inner {
    desired: TorMode,
    generation: u64,
    identity: Option<OnionIdentity>,
    consent_version: u32,
    running: Option<Running>,
    /// In-flight generation build; aborted on the next mode change.
    building: Option<tokio::task::JoinHandle<()>>,
    /// Node's transport inbound sender, parked until a generation's rend
    /// stream exists — `wire_inbound` is called once at node build time,
    /// before any generation is running.
    pending_inbound: Option<futures::channel::mpsc::Sender<arti_client::DataStream>>,
}

/// Owns the Tor lifecycle for one login session.
pub struct TorSupervisor {
    status_tx: watch::Sender<TorStatus>,
    inner: Arc<Mutex<Inner>>,
    tor_dir: PathBuf,
    /// Live client of the current generation — the node's `TorTransport`
    /// reads it at dial time. `None` whenever no generation is running.
    client_slot: Arc<std::sync::Mutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
}

impl TorSupervisor {
    /// `status_tx` receives every status transition; the handle keeps the
    /// receiver half.
    pub fn new(tor_dir: PathBuf, status_tx: watch::Sender<TorStatus>) -> Self {
        Self {
            status_tx,
            inner: Arc::new(Mutex::new(Inner {
                desired: TorMode::Off,
                generation: 0,
                identity: None,
                consent_version: 0,
                running: None,
                building: None,
                pending_inbound: None,
            })),
            tor_dir,
            client_slot: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Offline identity ensure: creates/opens the encrypted onion key. No
    /// sockets, no bootstrap, no descriptor publication.
    pub fn ensure_identity(&self, master: &[u8; 32]) -> Result<String> {
        let mut inner = self.lock()?;
        if let Some(id) = &inner.identity {
            self.set_status(|s| s.onion_address = Some(id.onion_address.clone()));
            return Ok(id.onion_address.clone());
        }
        let identity = ensure_onion_identity(master, &self.tor_dir)?;
        let addr = identity.onion_address.clone();
        inner.identity = Some(identity);
        self.set_status(|s| s.onion_address = Some(addr.clone()));
        Ok(addr)
    }

    /// Latest status snapshot; also performs the fatal-protocol check so a
    /// vendored-patch fatal is torn down on the next poll even if the
    /// monitor task has not run yet.
    pub fn status(&self) -> TorStatus {
        if let Ok(mut inner) = self.lock() {
            if let Some(running) = &inner.running {
                if let Some(reason) = running.client.protocol_fatal_reason() {
                    log::error!("Tor protocol fatal (patched exit(1)): {}", reason);
                    let running = inner.running.take();
                    inner.desired = TorMode::Off;
                    drop(inner);
                    self.set_status(|s| {
                        s.state = TorState::Failed;
                        s.error_code = Some("unsupported_version".into());
                    });
                    if let Some(r) = running {
                        Self::teardown(r);
                    }
                }
            }
        }
        self.status_tx.borrow().clone()
    }

    /// Desired mode change: tears the current generation down and, unless
    /// `mode == Off`, spawns a fresh generation build. `consent_version` is
    /// the version of consent text the user accepted — 0 = never consented,
    /// and nothing Tor-side is started.
    pub async fn set_desired(&self, mode: TorMode, consent_version: u32) -> Result<()> {
        log::info!("set_desired: mode={:?} consent_version={}", mode, consent_version);
        let generation = {
            let mut inner = self.lock()?;
            // Dedupe: an identical desired config with a live build or
            // running generation must NOT respawn. Aborting an in-flight
            // build mid-bootstrap can strand an arti client holding the
            // state-dir lock — the next build then blocks in
            // "Another process is bootstrapping the directory" forever.
            if inner.desired == mode
                && inner.consent_version == consent_version
                && (inner.building.is_some() || inner.running.is_some())
            {
                log::debug!("set_desired: already {:?} (build/run in flight) — no respawn", mode);
                return Ok(());
            }
            inner.desired = mode;
            inner.consent_version = consent_version;
            inner.generation += 1;
            if let Some(h) = inner.building.take() {
                h.abort();
            }
            inner.generation
        };
        self.stop_running().await?;
        if mode == TorMode::Off {
            self.set_status(|s| {
                s.state = TorState::Off;
                s.effective_mode = TorMode::Off;
                s.generation = generation;
                s.bootstrap_percent = 0;
                s.service_published = false;
            });
            return Ok(());
        }
        if super::handle::tor_disabled_by_env() {
            log::warn!("set_desired refused: NOID_DISABLE_TOR=1");
            self.set_status(|s| {
                s.state = TorState::Unsupported;
                s.error_code = Some("disabled_by_env".into());
            });
            return Ok(());
        }
        if consent_version == 0 {
            log::warn!("set_desired refused: consent_version=0 (user has not accepted Tor consent)");
            self.set_status(|s| {
                s.state = TorState::Off;
                s.error_code = Some("consent_required".into());
            });
            return Ok(());
        }
        // Identity must exist (login hook runs ensure_identity). Build the
        // service object under the lock-free path; the build task installs
        // the running generation itself so nothing is dropped on JoinHandle.
        let service = {
            let inner = self.lock()?;
            match inner.identity.as_ref().and_then(|id| id.build_service().ok()) {
                Some(s) => s,
                None => {
                    drop(inner);
                    log::warn!("set_desired refused: onion identity not ready (build_service failed)");
                    self.set_status(|s| {
                        s.state = TorState::Failed;
                        s.error_code = Some("identity_not_ready".into());
                    });
                    return Ok(());
                }
            }
        };
        log::info!("set_desired: spawning Tor generation {} build", generation);
        self.set_status(|s| {
            s.state = TorState::Starting;
            s.desired_mode = mode;
            s.effective_mode = TorMode::Off;
            s.generation = generation;
        });
        let inner_arc = self.inner.clone();
        let status_tx = self.status_tx.clone();
        let client_slot = self.client_slot.clone();
        let dir_state = self.tor_dir.join("arti-state");
        let dir_cache = self.tor_dir.join("arti-cache");
        let handle = tokio::spawn(async move {
            match build_generation(dir_state, dir_cache, status_tx.clone()).await {
                Ok(mut running) => {
                    match launch_service(&running.client, service).await {
                        Ok((svc, rend)) => {
                            running.service = Some(svc);
                            running.rend = Some(rend);
                            set_status(&status_tx, |s| {
                                s.state = TorState::Ready;
                                s.service_published = false; // reaches Ready when reachable — monitor updates
                                s.effective_mode = mode;
                            });
                            install(inner_arc, generation, running, &status_tx, &client_slot);
                        }
                        Err(e) => {
                            log::error!("Tor onion service launch failed: {}", e);
                            set_status(&status_tx, |s| {
                                s.state = TorState::Failed;
                                s.error_code = Some(sanitize_error(&e));
                            });
                        }
                    }
                }
                Err(e) => {
                    log::error!("Tor generation build failed: {}", e);
                    set_status(&status_tx, |s| {
                        s.state = TorState::Failed;
                        s.error_code = Some(sanitize_error(&e));
                    });
                }
            }
        });
        self.lock()?.building = Some(handle);
        Ok(())
    }

    /// The running client's `Arc` — `None` while no generation is running.
    /// Kept in a lockable slot so the node can read it lazily at dial time.
    pub fn client(&self) -> Option<Arc<TorClient<PreferredRuntime>>> {
        self.client_slot.lock().ok()?.clone()
    }

    /// Shared client slot for the node's `TorTransport` — resolved lazily
    /// at each dial, so the transport survives the bootstrap race and
    /// generation restarts.
    pub fn client_slot(
        &self,
    ) -> Arc<std::sync::Mutex<Option<Arc<TorClient<PreferredRuntime>>>>> {
        self.client_slot.clone()
    }

    /// Feed accepted inbound streams into the node's transport channel.
    /// Called once at node build time — possibly before any generation is
    /// running; the sender is parked and wired automatically when the next
    /// generation's rend stream appears.
    pub fn wire_inbound(&self, tx: futures::channel::mpsc::Sender<arti_client::DataStream>) -> bool {
        let Ok(mut inner) = self.lock() else { return false };
        if let Some(running) = inner.running.as_mut() {
            if running.accept.is_none() {
                if let Some(rend) = running.rend.take() {
                    running.accept = Some(super::accept_loop::spawn_accept_loop(rend, tx));
                    return true;
                }
            }
        }
        inner.pending_inbound = Some(tx);
        true
    }

    /// Full stop: desired=Off, teardown, no rebuild.
    pub async fn stop(&self) -> Result<()> {
        let consent = self.lock()?.consent_version;
        self.set_desired(TorMode::Off, consent).await
    }

    /// Teardown the running generation through the bounded barrier.
    async fn stop_running(&self) -> Result<()> {
        let running = self.lock()?.running.take();
        // Clear the client slot first so in-flight dials fail closed
        // instead of pinning a half-torn-down client.
        if let Ok(mut slot) = self.client_slot.lock() {
            *slot = None;
        }
        if let Some(r) = running {
            tokio::time::timeout(SHUTDOWN_BARRIER, async move {
                Self::teardown(r);
            })
            .await
            .context("tor shutdown barrier exceeded")?;
        }
        Ok(())
    }

    /// Orderly teardown: stop accepting, stop publishing, drop client
    /// (streams drain ~0.08s), abort the monitor and accept loop.
    fn teardown(running: Running) {
        drop(running.rend);
        if let Some(accept) = running.accept {
            accept.abort();
        }
        if let Some(svc) = running.service {
            drop(svc); // stops descriptor publication
        }
        running.monitor.abort();
        drop(running.client);
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| anyhow::anyhow!("tor supervisor lock poisoned"))
    }

    fn set_status(&self, f: impl FnOnce(&mut TorStatus)) {
        set_status(&self.status_tx, f);
    }
}

/// Install a built generation only if it is still the current one — a stale
/// generation (superseded by a later set_desired) is dropped instead.
fn install(
    inner: Arc<Mutex<Inner>>,
    generation: u64,
    mut running: Running,
    status_tx: &watch::Sender<TorStatus>,
    client_slot: &Arc<std::sync::Mutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
) {
    let Ok(mut inner) = inner.lock() else {
        return;
    };
    if inner.generation == generation {
        // Publish the client to the transport slot and wire any parked
        // inbound sender the node registered before bootstrap finished.
        if let Ok(mut slot) = client_slot.lock() {
            *slot = Some(running.client.clone());
        }
        if let Some(tx) = inner.pending_inbound.take() {
            if let Some(rend) = running.rend.take() {
                running.accept = Some(super::accept_loop::spawn_accept_loop(rend, tx));
            } else {
                inner.pending_inbound = Some(tx);
            }
        }
        inner.running = Some(running);
    } else {
        drop(inner);
        TorSupervisor::teardown(running);
        let _ = status_tx;
    }
}

fn set_status(tx: &watch::Sender<TorStatus>, f: impl FnOnce(&mut TorStatus)) {
    tx.send_modify(f);
}

fn sanitize_error(e: &anyhow::Error) -> String {
    // Status may be serialized to UI — keep only the coarse kind, no addrs.
    format!("{}", e).chars().take(64).collect()
}

/// Create an unbootstrapped client, watch its progress, bootstrap.
async fn build_generation(
    dir_state: PathBuf,
    dir_cache: PathBuf,
    status_tx: watch::Sender<TorStatus>,
) -> Result<Running> {
    // rustls needs a CryptoProvider before any TLS handshake — Android
    // never goes through main(), so the provider must be installed at the
    // choke point that EVERY entry path reaches. install_default() is
    // idempotent (returns Err on repeat — we ignore it).
    super::handle::install_crypto_provider();
    // fs_mistrust rejects world/group-accessible state dirs — arti's
    // storage layer hard-fails on 0755 parents, so create ours private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true).mode(0o700);
        b.create(&dir_state)?;
        b.create(&dir_cache)?;
        // Existing dirs from older runs keep their mode — tighten them
        // too (DirBuilder::create does not chmod existing entries).
        for d in [dir_state.as_path(), dir_cache.as_path()] {
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
        // The parent tor dir holds the encrypted keystore too.
        if let Some(parent) = dir_state.parent() {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir_state)?;
        std::fs::create_dir_all(&dir_cache)?;
    }
    let mut builder = TorClientConfigBuilder::from_directories(&dir_state, &dir_cache);
    // Noid keeps all key material in its own encrypted keystore; Arti's
    // native (unencrypted) keystore is disabled so no key file is written.
    builder
        .storage()
        .keystore()
        .enabled(arti_client::config::BoolOrAuto::Explicit(false));
    let config = builder.build().context("tor client config build")?;
    let client = TorClient::builder()
        .config(config)
        .create_unbootstrapped_async()
        .await
        .context("tor client create")?;

    // Progress monitor: maps bootstrap events onto TorStatus and watches the
    // vendored fatal flag until dropped.
    let monitor_client = client.clone();
    let monitor_tx = status_tx.clone();
    let monitor = tokio::spawn(async move {
        let mut events = monitor_client.bootstrap_events();
        loop {
            tokio::select! {
                ev = events.next() => {
                    let Some(status) = ev else { break };
                    if monitor_client.protocol_fatal_reason().is_some() {
                        set_status(&monitor_tx, |s| {
                            s.state = TorState::Failed;
                            s.error_code = Some("unsupported_version".into());
                        });
                        break;
                    }
                    let frac = (status.as_frac() * 100.0) as u8;
                    let ready = status.ready_for_traffic();
                    set_status(&monitor_tx, |s| {
                        if matches!(s.state, TorState::Starting | TorState::Bootstrapping) {
                            s.state = TorState::Bootstrapping;
                        }
                        s.bootstrap_percent = frac;
                    });
                    if ready {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    if monitor_client.protocol_fatal_reason().is_some() {
                        set_status(&monitor_tx, |s| {
                            s.state = TorState::Failed;
                            s.error_code = Some("unsupported_version".into());
                        });
                        break;
                    }
                }
            }
        }
    });

    tokio::time::timeout(BOOTSTRAP_TIMEOUT, client.bootstrap())
        .await
        .context("tor bootstrap timeout")?
        .context("tor bootstrap failed")?;
    Ok(Running { client, service: None, rend: None, monitor, accept: None })
}

/// Launch the onion service against the running client. Uses our custom
/// keymgr (encrypted keystore) — the client's native keystore stays disabled.
async fn launch_service(
    client: &Arc<TorClient<PreferredRuntime>>,
    service: tor_hsservice::OnionService,
) -> Result<(
    Arc<tor_hsservice::RunningOnionService>,
    std::pin::Pin<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send>>,
)> {
    let resolver = Arc::new(tor_config_path::CfgPathResolver::default());
    let out = service
        .launch(
            client.runtime().clone(),
            client.dirmgr()?,
            client.hs_circ_pool()?,
            resolver,
        )
        .context("onion service launch")?;
    let Some((running, rend)) = out else {
        anyhow::bail!("onion service disabled in config");
    };
    Ok((running, Box::pin(rend)))
}
