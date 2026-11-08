use arti_client::DataStream;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    identity::Keypair,
    noise, yamux, PeerId, Transport,
};
use std::time::Duration;

/// Compile-only native stream upgrade; the caller must still enforce expected PeerId.
pub fn upgrade_stream_transport<T>(
    transport: T,
    identity: &Keypair,
) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>>
where
    T: Transport<Output = DataStream> + Send + Unpin + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Dial: Send + 'static,
    T::ListenerUpgrade: Send + 'static,
{
    Ok(transport.upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(identity)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(30))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed())
}
