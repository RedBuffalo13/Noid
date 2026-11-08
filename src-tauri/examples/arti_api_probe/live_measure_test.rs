//! Opt-in live measurement: bootstrap timing, idle sampling, warm-cache
//! reconnect timing. RSS/CPU/connection counts are sampled externally by
//! measure_live_probe.ps1; this test only emits phase markers and ticks.
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tor_hsservice::config::OnionServiceConfigBuilder;

const IDLE_TICKS: u32 = 12;
const IDLE_TICK_SECS: u64 = 5;

fn config() -> Result<arti_client::config::TorClientConfig> {
    // NOID_PROBE_STATE_DIR pins state/cache so a second run measures a warm
    // bootstrap with retained directory data; default stays isolated temp.
    if let Ok(dir) = std::env::var("NOID_PROBE_STATE_DIR") {
        let root = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&root)?;
        return Ok(
            arti_client::config::TorClientConfigBuilder::from_directories(
                root.join("state"),
                root.join("cache"),
            )
            .build()?,
        );
    }
    super::live_probe_config::live_probe_config()
}

/// Run in its own process because CryptoProvider initialization is global.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_measure_bootstrap_idle() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("CryptoProvider init raced"))?;
    let cfg = config()?;
    tokio::time::timeout(Duration::from_secs(600), async {
        let start = Instant::now();
        eprintln!("LIVE_MEAS phase=bootstrap");
        let client = arti_client::TorClient::create_bootstrapped(cfg).await?;
        eprintln!(
            "LIVE_MEAS phase=bootstrap_done elapsed_ms={}",
            start.elapsed().as_millis()
        );
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname("noid-p0meas".parse()?)
            .build()?;
        let Some((running, rend)) = client.launch_onion_service(svc_cfg)? else {
            anyhow::bail!("launch_onion_service returned None")
        };
        eprintln!("LIVE_MEAS phase=service_launched has_addr={}", running.onion_address().is_some());
        // Idle window: external sampler records RSS/CPU/TCP-conn count per tick.
        for i in 0..IDLE_TICKS {
            tokio::time::sleep(Duration::from_secs(IDLE_TICK_SECS)).await;
            eprintln!("LIVE_MEAS phase=idle_tick n={}", i + 1);
        }
        eprintln!("LIVE_MEAS phase=idle_done");
        drop(rend);
        drop(running);
        drop(client);
        eprintln!("LIVE_MEAS phase=handles_dropped");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("live measure exceeded 600s")?
}
