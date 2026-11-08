//! Native libp2p `Transport` over `arti_client::DataStream` — onion dials and
//! inbound accept without any localhost SOCKS/TCP forward.
//!
//! Outbound: `/onion3/host:port` → `TorClient::connect` (120s Tor dial
//! timeout). Inbound: the supervisor's accept loop feeds accepted
//! `DataStream`s through `accept_tx`; `poll` turns them into `Incoming`
//! upgrades. The swarm's `.upgrade(Version::V1Lazy)` then runs
//! multistream/Noise/Yamux with expected-PeerId — identical to the P0 probe
//! `stream_contract` path.

use arti_client::{DataStream, TorClient};
use futures::{channel::mpsc, future::Ready, FutureExt, Stream};
use libp2p::{
    core::{
        transport::{DialOpts, ListenerId, TransportError, TransportEvent},
        Transport,
    },
    Multiaddr,
};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tor_rtcompat::PreferredRuntime;

use super::onion_addr;

/// Upgrade a `TorTransport` into a boxed `(PeerId, StreamMuxerBox)`
/// transport: multistream -> Noise -> Yamux with a 30s handshake budget —
/// the same contract the P0 probe proved over live onion streams.
pub fn upgrade(
    transport: TorTransport,
    key: &libp2p::identity::Keypair,
) -> Result<
    libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    Ok(transport
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(key)?)
        .multiplex(libp2p::yamux::Config::default())
        .timeout(Duration::from_secs(30))
        .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .boxed())
}

/// Tor dial timeout — longer than ordinary TCP because rendezvous setup is
/// slow; still bounded so a dead circuit can't hang the dialer forever.
const TOR_DIAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounded channel feeding accepted inbound streams into poll().
const INBOUND_CAP: usize = 16;

type TorTransportEvent = TransportEvent<Ready<Result<DataStream, io::Error>>, io::Error>;

/// Shared handle to the running generation's client — the supervisor
/// fills it on generation install and clears it on teardown, so the
/// transport can be registered before bootstrap finishes and survives
/// generation restarts.
pub type ClientSlot = Arc<std::sync::Mutex<Option<Arc<TorClient<PreferredRuntime>>>>>;

/// Onion transport: dial via `TorClient`, listen via the onion service's
/// accepted-stream channel.
pub struct TorTransport {
    client_slot: ClientSlot,
    accept_tx: mpsc::Sender<DataStream>,
    inbound: mpsc::Receiver<DataStream>,
    listen_addr: Option<Multiaddr>,
    listener_id: Option<ListenerId>,
    pending: VecDeque<TorTransportEvent>,
}

impl TorTransport {
    /// `accept_tx()` hands the sender half to the service accept loop — one
    /// `DataStream` per accepted rendezvous on the Noid virtual port.
    pub fn new(client_slot: ClientSlot) -> Self {
        let (accept_tx, inbound) = mpsc::channel(INBOUND_CAP);
        Self {
            client_slot,
            accept_tx,
            inbound,
            listen_addr: None,
            listener_id: None,
            pending: VecDeque::new(),
        }
    }

    pub fn accept_tx(&self) -> mpsc::Sender<DataStream> {
        self.accept_tx.clone()
    }
}

impl Transport for TorTransport {
    type Output = DataStream;
    type Error = io::Error;
    type ListenerUpgrade = Ready<Result<Self::Output, Self::Error>>;
    type Dial =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        // Only our canonical onion3 form is listable; anything else is not
        // this transport's address family.
        if onion_addr::parse(&addr).is_none() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        self.listen_addr = Some(addr.clone());
        self.listener_id = Some(id);
        self.pending.push_back(TransportEvent::NewAddress {
            listener_id: id,
            listen_addr: addr,
        });
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        if self.listener_id == Some(id) {
            self.listen_addr = None;
            self.listener_id = None;
            return true;
        }
        false
    }

    fn dial(&mut self, addr: Multiaddr, _opts: DialOpts) -> Result<Self::Dial, TransportError<Self::Error>> {
        let Some(parsed) = onion_addr::parse(&addr) else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        let client = self
            .client_slot
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| {
                TransportError::Other(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "tor client not ready",
                ))
            })?;
        let target = (format!("{}.onion", parsed.host), parsed.port);
        Ok(async move {
            match tokio::time::timeout(TOR_DIAL_TIMEOUT, client.connect(target)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(io::Error::other(format!("tor dial: {}", e))),
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "tor dial timeout")),
            }
        }
        .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TorTransportEvent> {
        if let Some(ev) = self.pending.pop_front() {
            return Poll::Ready(ev);
        }
        match Pin::new(&mut self.inbound).poll_next(cx) {
            Poll::Ready(Some(stream)) => {
                let listen_addr = self
                    .listen_addr
                    .clone()
                    .unwrap_or_else(|| "/onion3/unknown:0".parse().unwrap());
                Poll::Ready(TransportEvent::Incoming {
                    listener_id: self.listener_id.unwrap_or_else(ListenerId::next),
                    upgrade: futures::future::ready(Ok(stream)),
                    local_addr: listen_addr.clone(),
                    send_back_addr: listen_addr,
                })
            }
            Poll::Ready(None) => Poll::Pending, // accept loop gone; stay idle
            Poll::Pending => Poll::Pending,
        }
    }
}
