use anyhow::{ensure, Context, Result};
use futures::{future::poll_fn, Future};
use libp2p::{
    core::{
        muxing::{StreamMuxer, StreamMuxerBox},
        transport::{memory::MemoryTransport, DialOpts, ListenerId, PortUse, TransportEvent},
        upgrade::Version,
        Endpoint,
    },
    identity::Keypair,
    noise, yamux, Transport,
};
use std::{pin::Pin, task::Poll, time::Duration};

/// Negotiate multistream/Noise/Yamux without sockets, then exchange on a substream.
#[tokio::test]
async fn memory_transport_negotiates_authenticated_muxed_stream() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let client_key = Keypair::generate_ed25519();
        let server_key = Keypair::generate_ed25519();
        let client_peer = client_key.public().to_peer_id();
        let server_peer = server_key.public().to_peer_id();
        let [client, server] = [client_key, server_key].map(|key| {
            Ok::<_, anyhow::Error>(
                MemoryTransport::default()
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise::Config::new(&key)?)
                    .multiplex(yamux::Config::default())
                    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                    .boxed(),
            )
        });
        let mut client = client?;
        let mut server = server?;
        server.listen_on(ListenerId::next(), "/memory/0".parse()?)?;
        let address = loop {
            match poll_fn(|cx| Pin::new(&mut server).poll(cx)).await {
                TransportEvent::NewAddress { listen_addr, .. } => break listen_addr,
                TransportEvent::ListenerError { error, .. } => return Err(error.into()),
                _ => {}
            }
        };
        let dial = client.dial(
            address,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )?;
        let accept = async {
            loop {
                match poll_fn(|cx| Pin::new(&mut server).poll(cx)).await {
                    TransportEvent::Incoming { upgrade, .. } => return upgrade.await,
                    TransportEvent::ListenerError { error, .. } => return Err(error),
                    _ => {}
                }
            }
        };
        futures::pin_mut!(dial, accept);
        let mut dialed = None;
        let mut accepted = None;
        // V1Lazy may finish one upgrade before its peer. Poll its muxer while
        // the other upgrade is pending, just as a running Swarm would do.
        let ((remote_server, mut client_muxer), (remote_client, mut server_muxer)) =
            poll_fn(|cx| {
                if dialed.is_none() {
                    if let Poll::Ready(result) = dial.as_mut().poll(cx) {
                        dialed = Some(result?);
                    }
                }
                if accepted.is_none() {
                    if let Poll::Ready(result) = accept.as_mut().poll(cx) {
                        accepted = Some(result?);
                    }
                }
                if dialed.is_some() && accepted.is_some() {
                    return Poll::Ready(Ok::<_, std::io::Error>((
                        dialed
                            .take()
                            .ok_or_else(|| std::io::Error::other("missing dial"))?,
                        accepted
                            .take()
                            .ok_or_else(|| std::io::Error::other("missing accept"))?,
                    )));
                }
                for (_, muxer) in dialed.iter_mut().chain(accepted.iter_mut()) {
                    match Pin::new(muxer).poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            })
            .await?;
        ensure!(remote_server == server_peer, "unexpected server PeerId");
        ensure!(remote_client == client_peer, "unexpected client PeerId");
        let both_done = tokio::sync::Barrier::new(2);
        futures::try_join!(
            super::exchange_muxed_probe::exchange_muxed_probe(&mut client_muxer, true, &both_done),
            super::exchange_muxed_probe::exchange_muxed_probe(&mut server_muxer, false, &both_done)
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("memory transport stack exceeded 5s")?
}
