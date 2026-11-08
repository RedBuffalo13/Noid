use std::net::UdpSocket;

/// Generation-tagged clone of the active listener's UDP socket.
pub(super) struct RegisteredListenerSocket {
    pub(super) generation: u64,
    pub(super) socket: UdpSocket,
}
