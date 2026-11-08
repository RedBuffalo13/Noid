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

/// Spawn the accept task. Returns the JoinHandle so the supervisor owns it
/// inside the generation (shutdown barrier covers it).
pub fn spawn_accept_loop(
    rend: impl Stream<Item = RendRequest> + Send + Unpin + 'static,
    tx: mpsc::Sender<DataStream>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(accept_loop(rend, tx))
}

async fn accept_loop(
    mut rend: impl Stream<Item = RendRequest> + Send + Unpin,
    tx: mpsc::Sender<DataStream>,
) {
    while let Some(request) = rend.next().await {
        let mut tx = tx.clone();
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
