use anyhow::{ensure, Context, Result};
use libp2p::identity::Keypair;
use std::time::Duration;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Accept the expected identity and fail closed on either mismatched PeerId.
#[tokio::test]
async fn noise_checks_expected_peer_before_application_bytes() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let client_key = Keypair::generate_ed25519();
        let server_key = Keypair::generate_ed25519();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        for reject_side in [None, Some(true), Some(false)] {
            let (client, server) = tokio::io::duplex(4096);
            let client_expected = if reject_side == Some(true) {
                other
            } else {
                server_key.public().to_peer_id()
            };
            let server_expected = if reject_side == Some(false) {
                other
            } else {
                client_key.public().to_peer_id()
            };
            let (client, server) = futures::join!(
                super::authenticate_probe_stream::authenticate_probe_stream(
                    client.compat(),
                    &client_key,
                    client_expected,
                    true
                ),
                super::authenticate_probe_stream::authenticate_probe_stream(
                    server.compat(),
                    &server_key,
                    server_expected,
                    false
                )
            );
            match reject_side {
                Some(true) => ensure!(client.is_err(), "wrong server identity was accepted"),
                Some(false) => ensure!(server.is_err(), "wrong client identity was accepted"),
                None => {
                    futures::try_join!(
                        super::probe_exchange::probe_exchange(client?, true),
                        super::probe_exchange::probe_exchange(server?, false)
                    )?;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("offline Noise proof exceeded 5s")?
}
