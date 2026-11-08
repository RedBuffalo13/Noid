use super::{IPV4_LISTENER_SOCKET, IPV6_LISTENER_SOCKET};

/// Snapshot the active listener generation; stale mapping writes are rejected.
pub fn listener_generation(ipv6: bool) -> Option<u64> {
    let slot = if ipv6 {
        &IPV6_LISTENER_SOCKET
    } else {
        &IPV4_LISTENER_SOCKET
    };
    slot.read().ok()?.as_ref().map(|entry| entry.generation)
}
