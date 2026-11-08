//! Opt-in authenticated onion proof: raw PING/PONG replaced by the full
//! Noise handshake with an expected-PeerId check inside the live onion stream.
//! Requires a shared identity file generated offline; run per-process.
use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::identity::Keypair;
use safelog::DisplayRedacted;
use std::time::Duration;
use tor_hsservice::config::OnionServiceConfigBuilder;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_noise_over_onion_authenticated() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("run one live test per process"))?;
    let server_key = Keypair::generate_ed25519();
    let client_key = Keypair::generate_ed25519();
    let server_peer = server_key.public().to_peer_id();
    let client_peer = client_key.public().to_peer_id();
    let config = super::live_probe_config::live_probe_config()?;
    tokio::time::timeout(Duration::from_secs(600), async {
        let client = arti_client::TorClient::create_bootstrapped(config).await?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname("noid-p0live".parse()?)
            .build()?;
        let Some((running, mut rend)) = client.launch_onion_service(svc_cfg)? else {
            anyhow::bail!("launch returned None")
        };
        let address = running.onion_address().context("no onion address")?;
        let onion = format!("{}:4020", address.display_unredacted());
        let mut statuses = running.status_events();
        tokio::time::timeout(Duration::from_secs(300), async {
            while !running.status().state().is_fully_reachable() {
                statuses.next().await.context("status stream ended")?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("publication exceeded 300s")??;
        eprintln!("LIVE_P0 phase=reported_reachable");
        let server = async {
            let request = rend.next().await.context("rendezvous ended")?;
            let mut requests = request.accept().await?;
            let request = requests.next().await.context("no stream request")?;
            let stream = crate::accept_stream(request).await?;
            let mut secured = super::authenticate_probe_stream::authenticate_probe_stream(
                stream,
                &server_key,
                client_peer,
                false,
            )
            .await?;
            eprintln!("LIVE_P0 phase=server_noise_exchange");
            super::probe_exchange::probe_exchange(&mut secured, false).await?;
            drop(requests);
            Ok::<_, anyhow::Error>(secured)
        };
        let consumer = client.isolated_client();
        let connector = async {
            let stream = consumer.connect(&*onion).await.context("connect")?;
            let mut secured = super::authenticate_probe_stream::authenticate_probe_stream(
                stream,
                &client_key,
                server_peer,
                true,
            )
            .await?;
            eprintln!("LIVE_P0 phase=client_noise_exchange");
            super::probe_exchange::probe_exchange(&mut secured, true).await
        };
        tokio::time::timeout(Duration::from_secs(180), async {
            let joined = futures::try_join!(server, connector)?;
            Ok::<_, anyhow::Error>(joined)
        })
        .await
        .context("noise exchange exceeded 180s")??;
        eprintln!("LIVE_P0 phase=noise_onion_passed (shutdown gate remains open)");
        drop(statuses);
        drop(running);
        drop(consumer);
        drop(client);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("live Noise-over-onion exceeded 600s")?
}
