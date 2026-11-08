//! Opt-in raw onion exchange. This is not a Noise/Yamux authentication proof.
use anyhow::{Context, Result};
use futures::StreamExt;
use safelog::DisplayRedacted;
use std::time::Duration;
use tor_hsservice::config::OnionServiceConfigBuilder;

/// Bound the complete async scenario, including accept and buffered reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_onion_stream_bidirectional() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("run one live test per process"))?;
    let config = super::live_probe_config::live_probe_config()?;
    tokio::time::timeout(Duration::from_secs(600), async {
        eprintln!("LIVE_P0 phase=bootstrap");
        let client = arti_client::TorClient::create_bootstrapped(config).await?;
        eprintln!("LIVE_P0 phase=launch");
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname("noid-p0live".parse()?)
            .build()?;
        let Some((running, mut rend)) = client.launch_onion_service(svc_cfg)? else {
            anyhow::bail!("launch returned None")
        };
        let address = running.onion_address().context("no onion address")?;
        let onion = format!("{}:4020", address.display_unredacted());
        let mut statuses = running.status_events();
        eprintln!("LIVE_P0 phase=publication_wait");
        tokio::time::timeout(Duration::from_secs(300), async {
            while !running.status().state().is_fully_reachable() {
                statuses.next().await.context("status stream ended")?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("publication exceeded 300s")??;
        eprintln!("LIVE_P0 phase=reported_reachable");

        // No detached task: cancellation drops both futures and their streams.
        let server = async {
            let request = rend.next().await.context("rendezvous stream ended")?;
            eprintln!("LIVE_P0 phase=rendezvous_accept");
            let mut requests = request.accept().await?;
            let request = requests.next().await.context("no stream request")?;
            let mut stream = crate::accept_stream(request).await?;
            eprintln!("LIVE_P0 phase=server_exchange");
            super::probe_exchange::probe_exchange(&mut stream, false).await?;
            // RendRequest::accept keeps its tunnel alive through `requests`.
            // Retain both until the client has consumed the flushed response.
            Ok::<_, anyhow::Error>((stream, requests))
        };
        let consumer = client.isolated_client();
        let connector = async {
            eprintln!("LIVE_P0 phase=connect");
            let stream = consumer
                .connect(&*onion)
                .await
                .context("onion connect failed")?;
            eprintln!("LIVE_P0 phase=client_exchange");
            super::probe_exchange::probe_exchange(stream, true).await
        };
        let ((server_stream, requests), ()) =
            tokio::time::timeout(Duration::from_secs(180), async {
                futures::try_join!(server, connector)
            })
            .await
            .context("connect/accept/exchange exceeded 180s")??;
        drop(server_stream);
        drop(requests);
        drop(statuses);
        drop(rend);
        drop(running);
        drop(consumer);
        drop(client);
        eprintln!("LIVE_P0 phase=raw_exchange_passed (Noise/shutdown gates remain open)");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("entire live onion scenario exceeded 600s")?
}
