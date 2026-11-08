//! Opt-in bootstrap/launch smoke, not a publication or shutdown proof.
use anyhow::{ensure, Context, Result};
use std::time::{Duration, Instant};
use tor_hsservice::config::OnionServiceConfigBuilder;

/// Run in its own process because CryptoProvider initialization is global.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_bootstrap_service_and_shutdown() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("CryptoProvider init raced"))?;
    let cfg = super::live_probe_config::live_probe_config()?;
    tokio::time::timeout(Duration::from_secs(180), async {
        let start = Instant::now();
        eprintln!("LIVE_P0 phase=bootstrap");
        let client = arti_client::TorClient::create_bootstrapped(cfg).await?;
        eprintln!(
            "LIVE_P0 phase=bootstrap_done elapsed_ms={}",
            start.elapsed().as_millis()
        );
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname("noid-p0live".parse()?)
            .build()?;
        let Some((running, rend)) = client.launch_onion_service(svc_cfg)? else {
            anyhow::bail!("launch_onion_service returned None")
        };
        ensure!(
            running.onion_address().is_some(),
            "missing local onion address"
        );
        drop(rend);
        drop(running);
        drop(client);
        eprintln!("LIVE_P0 phase=handles_dropped (internal task drain NOT asserted)");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("bootstrap/launch exceeded 180s")?
}
