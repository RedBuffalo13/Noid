use libp2p::{autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response, upnp};
use crate::p2p::types::{NoidMessage, NoidResponse, MailboxRequest, MailboxResponse};

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "NoidBehaviourEvent")]
pub struct NoidBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    /// Toggle-wrapped so a failed multicast init (restricted platforms like
    /// Android) disables LAN discovery instead of aborting the node.
    /// Transparent to events — `NoidBehaviourEvent::Mdns` stays `mdns::Event`.
    pub mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<crate::p2p::validating_store::ValidatingStore>,
    pub request_response: request_response::json::Behaviour<NoidMessage, NoidResponse>,
    pub relay: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    /// NAT reachability measurement (client probes via other peers,
    /// server side lets us probe others).
    pub autonat: autonat::Behaviour,
    /// UPnP/NAT-PMP port mapping on the local gateway — Toggle so a strict
    /// (`tor_only`) build can disable the LAN socket path entirely.
    pub upnp: libp2p::swarm::behaviour::toggle::Toggle<upnp::tokio::Behaviour>,
    /// Phase B.2: Mailbox protocol for offline message delivery
    pub mailbox: request_response::json::Behaviour<MailboxRequest, MailboxResponse>,
    /// META-05: /noid-hop/1.0.0 — onion-style request forwarding for the
    /// 2-hop privacy relay (entry sees next-hop only, exit sees dest only).
    pub hop: request_response::json::Behaviour<crate::p2p::hop::HopRequest, crate::p2p::hop::HopResponse>,
    /// SEC-06: hard cap on pending/established connections so a flood of
    /// inbound dials or a dial storm cannot exhaust sockets and memory.
    pub limits: libp2p::connection_limits::Behaviour,
}

#[derive(Debug)]
pub enum NoidBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(kad::Event),
    RequestResponse(request_response::Event<NoidMessage, NoidResponse>),
    Relay(relay::Event),
    RelayClient(relay::client::Event),
    Dcutr(dcutr::Event),
    Autonat(autonat::Event),
    Upnp(upnp::Event),
    /// Phase B.2: Mailbox protocol events
    Mailbox(request_response::Event<MailboxRequest, MailboxResponse>),
    Hop(request_response::Event<crate::p2p::hop::HopRequest, crate::p2p::hop::HopResponse>),
    /// connection_limits emits no events — Infallible is uninhabited.
    Limits(std::convert::Infallible),
}

impl From<gossipsub::Event> for NoidBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        NoidBehaviourEvent::Gossipsub(event)
    }
}

impl From<mdns::Event> for NoidBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        NoidBehaviourEvent::Mdns(event)
    }
}

impl From<ping::Event> for NoidBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        NoidBehaviourEvent::Ping(event)
    }
}

impl From<identify::Event> for NoidBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        NoidBehaviourEvent::Identify(Box::new(event))
    }
}

impl From<kad::Event> for NoidBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        NoidBehaviourEvent::Kademlia(event)
    }
}

impl From<request_response::Event<NoidMessage, NoidResponse>> for NoidBehaviourEvent {
    fn from(event: request_response::Event<NoidMessage, NoidResponse>) -> Self {
        NoidBehaviourEvent::RequestResponse(event)
    }
}

impl From<dcutr::Event> for NoidBehaviourEvent {
    fn from(event: dcutr::Event) -> Self {
        NoidBehaviourEvent::Dcutr(event)
    }
}

impl From<relay::client::Event> for NoidBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        NoidBehaviourEvent::RelayClient(event)
    }
}

impl From<relay::Event> for NoidBehaviourEvent {
    fn from(event: relay::Event) -> Self {
        NoidBehaviourEvent::Relay(event)
    }
}

impl From<autonat::Event> for NoidBehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        NoidBehaviourEvent::Autonat(event)
    }
}

impl From<upnp::Event> for NoidBehaviourEvent {
    fn from(event: upnp::Event) -> Self {
        NoidBehaviourEvent::Upnp(event)
    }
}

impl From<request_response::Event<MailboxRequest, MailboxResponse>> for NoidBehaviourEvent {
    fn from(event: request_response::Event<MailboxRequest, MailboxResponse>) -> Self {
        NoidBehaviourEvent::Mailbox(event)
    }
}

impl From<request_response::Event<crate::p2p::hop::HopRequest, crate::p2p::hop::HopResponse>> for NoidBehaviourEvent {
    fn from(event: request_response::Event<crate::p2p::hop::HopRequest, crate::p2p::hop::HopResponse>) -> Self {
        NoidBehaviourEvent::Hop(event)
    }
}

impl From<std::convert::Infallible> for NoidBehaviourEvent {
    fn from(event: std::convert::Infallible) -> Self {
        match event {}
    }
}
