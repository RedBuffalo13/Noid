use super::{
    probe_socket_sync, set_observed_stun_mapping, ListenerSocketRegistration,
    RegisteredListenerSocket, IPV4_LISTENER_SOCKET, IPV6_LISTENER_SOCKET, NEXT_LISTENER_GENERATION,
    OBSERVED_MAPPING,
};
use std::net::UdpSocket;
use std::sync::atomic::Ordering;

/// Called by `GenTransport::listen_on` right after `create_socket` binds the
/// UDP socket and before `quinn::Endpoint` starts reading from it.
pub(crate) fn on_listener_socket_bound(
    socket: &UdpSocket,
    is_ipv6: bool,
) -> Option<ListenerSocketRegistration> {
    let cloned = socket.try_clone().ok()?;
    let generation = NEXT_LISTENER_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()?;
    let registration = ListenerSocketRegistration {
        generation,
        ipv6: is_ipv6,
    };
    let lock = if is_ipv6 {
        &IPV6_LISTENER_SOCKET
    } else {
        &IPV4_LISTENER_SOCKET
    };
    {
        let mut current = lock.write().ok()?;
        *current = Some(RegisteredListenerSocket {
            generation,
            socket: cloned,
        });
        if !is_ipv6 {
            if let Ok(mut mapping) = OBSERVED_MAPPING.write() {
                *mapping = None;
            }
        }
    }

    // Perform a fast initial STUN probe on the IPv4 QUIC socket before quinn
    // attaches its async reactor, so we learn the exact external port mapped
    // to our QUIC listener.
    if !is_ipv6 {
        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        // Skip loopback-only binds (unit tests).
        let is_loopback = socket
            .local_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !is_loopback && std::env::var_os("NOID_DISABLE_STUN").is_none() {
            if let Some(mapping) = probe_socket_sync(socket, local_port) {
                set_observed_stun_mapping(generation, mapping);
            }
        }
    }
    Some(registration)
}
