//! Offline shutdown proof: dropping the last TorClient must close
//! internal event streams, evidencing task teardown without the network.
use anyhow::{ensure, Context, Result};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_client_closes_internal_streams() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("provider raced — run alone"))?;
    let cfg = super::live_probe_config::live_probe_config()?;
    let client = arti_client::TorClient::builder().config(cfg).create_unbootstrapped_async().await?;
    let mut events = client.bootstrap_events();
    let weak = Arc::downgrade(&client);
    drop(client);
    // bootstrap_events producer lives in client internals; if tasks keep
    // running and hold it, this stream never ends -> fail closed via timeout.
    tokio::time::timeout(Duration::from_secs(10), async {
        while events.next().await.is_some() {}
    })
    .await
    .context("internal event stream did not close within 10s")?;
    ensure!(
        weak.upgrade().is_none(),
        "TorClient inner state survived drop"
    );
    Ok(())
}
