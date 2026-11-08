use anyhow::Result;
use futures::{future::poll_fn, Future};
use libp2p::core::muxing::StreamMuxer;
use std::{pin::Pin, task::Poll};

/// Drive a muxer throughout opening and exchanging on one probe substream.
pub(super) async fn exchange_muxed_probe<M>(
    muxer: &mut M,
    initiator: bool,
    both_done: &tokio::sync::Barrier,
) -> Result<()>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
    M::Error: Send + Sync + 'static,
{
    let mut stream = poll_fn(|cx| {
        match Pin::new(&mut *muxer).poll(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        if initiator {
            Pin::new(&mut *muxer).poll_outbound(cx)
        } else {
            Pin::new(&mut *muxer).poll_inbound(cx)
        }
    })
    .await?;
    let exchange = async {
        super::probe_exchange::probe_exchange(&mut stream, initiator).await?;
        // A substream flush can enqueue frames that still require muxer polling.
        both_done.wait().await;
        Ok::<_, anyhow::Error>(())
    };
    futures::pin_mut!(exchange);
    poll_fn(|cx| {
        match Pin::new(&mut *muxer).poll(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        exchange.as_mut().poll(cx)
    })
    .await
}
