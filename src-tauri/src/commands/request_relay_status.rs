use crate::p2p::{P2PCommand, RelayStatus};
use crate::AppState;

/// Fetch a fresh relay/NAT status snapshot from the running event loop.
///
/// `ReportRelayStatus` replies through a oneshot, so this returns the live
/// snapshot instead of the asynchronously maintained `state.relay_status`
/// cache — reading that cache right after sending the command races the
/// event-loop response and yields stale data. Falls back to the cache when
/// the node is down or the reply times out.
pub async fn request_relay_status(state: &AppState) -> RelayStatus {
    if let Some(tx) = state.p2p() {
        let (respond_to, rx) = tokio::sync::oneshot::channel();
        if crate::send_p2p_cmd(&tx, P2PCommand::ReportRelayStatus { respond_to })
            .await
            .is_ok()
        {
            if let Ok(Ok(status)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), rx).await
            {
                return status;
            }
        }
    }
    state.relay_status.lock().await.clone()
}
