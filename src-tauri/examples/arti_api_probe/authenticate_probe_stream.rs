use anyhow::{ensure, Context, Result};
use futures::{AsyncRead, AsyncWrite};
use libp2p::{
    core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo},
    identity::Keypair,
    noise, PeerId,
};

/// Exercise Noise directly and reject a mismatched expected Noid identity.
///
/// This probe helper does not negotiate multistream or construct Yamux.
pub(super) async fn authenticate_probe_stream<S>(
    stream: S,
    identity: &Keypair,
    expected: PeerId,
    initiator: bool,
) -> Result<noise::Output<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = noise::Config::new(identity)?;
    let protocol = config.protocol_info().next().context("no Noise protocol")?;
    let (remote, secured) = if initiator {
        config.upgrade_outbound(stream, protocol).await?
    } else {
        config.upgrade_inbound(stream, protocol).await?
    };
    ensure!(
        remote == expected,
        "Noise authenticated an unexpected PeerId"
    );
    Ok(secured)
}
