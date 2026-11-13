//! RV-05: onion-service self-connect probe — the only end-to-end proof
//! that our HSDir descriptor is published and the service accepts
//! rendezvous. `RunningOnionService::status().is_fully_reachable()` covers
//! intro-point liveness only; observed logs show upload timeouts leaving a
//! "reachable" service undialable for minutes. A real `TorClient::connect`
//! to our own `.onion` walks the inviter's path: descriptor fetch → intro
//! → rendezvous → our accept loop upgrades it like any peer's.
//!
//! Rate limits are the supervisor's job; this module just runs one probe.
//! The established stream is dropped immediately — our listener sees a
//! short inbound conn that closes during the Noise upgrade (harmless, and
//! it even feeds verified-by-inbound evidence).

use std::sync::Arc;
use std::time::Duration;

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

/// Probe budget — cold descriptor fetches on a degraded guard set are
/// slow; 90s matches the req-resp cold-Tor timeout policy.
const PROBE_TIMEOUT: Duration = Duration::from_secs(90);

/// True when a `TorClient::connect` to our own onion service succeeded —
/// descriptor published, intro reachable, rendezvous completed.
/// `onion_host` is the 56-char v3 name without `.onion` suffix.
pub async fn probe_self_service(
    client: Arc<TorClient<PreferredRuntime>>,
    onion_host: &str,
    vport: u16,
) -> bool {
    let host = format!("{}.onion", onion_host);
    let target = (host.as_str(), vport);
    match tokio::time::timeout(PROBE_TIMEOUT, client.connect(target)).await {
        Ok(Ok(_stream)) => {
            log::info!(
                "onion self-probe {}:{} — descriptor+rendezvous verified",
                host,
                vport
            );
            true
        }
        Ok(Err(e)) => {
            log::info!("onion self-probe {}:{} failed: {}", host, vport, e);
            false
        }
        Err(_) => {
            log::info!("onion self-probe {}:{} timed out", host, vport);
            false
        }
    }
}
