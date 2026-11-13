//! Inbound onion accept loop: drains the `RendRequest` stream from the
//! launched service, accepts each rendezvous, filters `StreamRequest`s to
//! the Noid virtual port, and feeds the resulting `DataStream`s into the
//! `TorTransport` inbound channel.
//!
//! The `RendRequest`'s returned request-stream is HELD for the life of the
//! accept loop (probe-proven contract: dropping it tears the rendezvous
//! tunnel down).

use anyhow::Result;
use arti_client::DataStream;
use futures::{channel::mpsc, SinkExt, Stream, StreamExt};
use tor_cell::relaycell::msg::{Connected, End};
use tor_hsservice::{RendRequest, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;

use super::onion_addr::ONION_VPORT;

/// Hot-swappable inbound destination: the node's `TorTransport` sender is
/// replaced by `wire_inbound` whenever a new P2PNode generation starts
/// (re-login after `lock_now`, transport rebuild) WITHOUT restarting the
/// Tor generation — so the accept loop survives node restarts and never
/// drops inbound streams into a dead channel.
pub type InboundSlot =
    std::sync::Arc<std::sync::Mutex<Option<mpsc::Sender<DataStream>>>>;

/// Spawn the accept task. Returns the JoinHandle so the supervisor owns it
/// inside the generation (shutdown barrier covers it).
pub fn spawn_accept_loop(
    rend: impl Stream<Item = RendRequest> + Send + Unpin + 'static,
    slot: InboundSlot,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(accept_loop(rend, slot))
}

async fn accept_loop(
    mut rend: impl Stream<Item = RendRequest> + Send + Unpin,
    slot: InboundSlot,
) {
    while let Some(request) = rend.next().await {
        // Resolve the current transport sender per rendezvous — the slot
        // may hold a sender whose receiver died with the last node, or
        // be empty between node generations.
        let tx = slot
            .lock()
            .ok()
            .and_then(|g| g.clone());
        let Some(mut tx) = tx else {
            continue; // no live transport right now — drop the rendezvous
        };
        tokio::spawn(async move {
            // accept() returns the StreamRequest stream — it must outlive the
            // exchange or the tunnel dies (probe finding, live 56.44s test).
            match request.accept().await {
                Ok(mut requests) => {
                    while let Some(req) = requests.next().await {
                        if let Ok(stream) = accept_stream(req).await {
                            if tx.send(stream).await.is_err() {
                                return; // transport gone
                            }
                        }
                    }
                }
                Err(e) => log::warn!("onion rendezvous accept failed: {}", e),
            }
        });
    }
}

/// Accept only BEGIN on the Noid virtual port; reject everything else.
async fn accept_stream(request: StreamRequest) -> Result<DataStream> {
    if matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == ONION_VPORT)
    {
        return Ok(request.accept(Connected::new_empty()).await?);
    }
    request.reject(End::new_misc()).await?;
    anyhow::bail!("unsupported onion virtual port")
}
