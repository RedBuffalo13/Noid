//! Behaviour-set construction shared by every transport policy.
//!
//! `direct_discovery` gates LAN-facing behaviours: mDNS and UPnP create
//! local multicast/UDP sockets — under `tor_only` they are disabled so no
//! direct-network code path exists at all.
use anyhow::{anyhow, Result};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response, upnp,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::p2p::behaviour::NoidBehaviour;

pub fn build_behaviour(
    key: &libp2p::identity::Keypair,
    relay_client: relay::client::Behaviour,
    relay_behaviour_config: relay::Config,
    direct_discovery: bool,
) -> Result<NoidBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|msg| anyhow!("Gossipsub config error: {msg}"))?;

    // META-04: anonymous gossipsub — every message is already sealed inside
    // a RoomEnvelope (V2 hides even that), so the libp2p-layer sender
    // signature only leaked the publisher's PeerId to transit peers.
    // Envelope signatures still authenticate authors for members.
    let _ = key;
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Anonymous,
        gossipsub_config,
    )?;

    // mDNS joins a multicast group, which can fail on restricted platforms
    // (Android without a held multicast lock, containers). It is LAN
    // discovery only — degrade gracefully instead of failing the whole
    // swarm build. `tor_only` disables it outright (no LAN sockets).
    let mdns = libp2p::swarm::behaviour::toggle::Toggle::from(if direct_discovery {
        match mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            key.public().to_peer_id(),
        ) {
            Ok(behaviour) => Some(behaviour),
            Err(e) => {
                log::warn!("mDNS unavailable, LAN discovery disabled: {}", e);
                None
            }
        }
    } else {
        None
    });

    // D12/D15: isolate the DHT from generic IPFS-kad traffic.
    // A custom protocol name keeps foreign kad peers out entirely,
    // and FilterBoth makes the local store reject incoming PUT_VALUEs
    // for records we did not ask to keep (limits store spam); noid:*
    // record signatures are still verified by the reader.
    let mut kad_config = kad::Config::new(
        libp2p::StreamProtocol::new("/noid/kad/1.0.0"),
    );
    kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
    // D15: signature-checked store — foreign/unsigned records are
    // refused instead of silently overwriting valid noid entries.
    let store = crate::p2p::validating_store::ValidatingStore::new(
        key.public().to_peer_id(),
    );
    let kademlia = kad::Behaviour::with_config(
        key.public().to_peer_id(),
        store,
        kad_config,
    );

    let request_response = request_response::json::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/noid/1.0.0"),
            request_response::ProtocolSupport::Full,
        )],
        // EL-05: the 10s default raced the app-ack window — the
        // receiver answers only after its app layer reports durable
        // processing (SQLite write + decrypt), which on Android cold
        // paths exceeds 10s and produced phantom MessageFailed +
        // resend storms. 90s also covers a cold Tor rendezvous build
        // (~45-90s on mobile), which used to abort ContactRequests
        // mid-handshake.
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(90)),
    );

    // Phase B.2: Mailbox protocol for offline message delivery.
    // F7: bulk Retrieve over a byte-capped circuit can carry ~200
    // envelopes — the default 10s request timeout aborts mid-transfer
    // and used to kill the reservation conn. Give mailbox 90s.
    let mailbox = request_response::json::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/noid-mailbox/1.0.0"),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(90)),
    );

    // META-05: hop-forwarding for the 2-hop privacy relay. Generous
    // timeout — a request traverses two full req-resp round trips.
    let hop = request_response::json::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/noid-hop/1.0.0"),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(90)),
    );

    Ok(NoidBehaviour {
        gossipsub,
        mdns,
        // CGNAT (Tele2) evicts the flow mapping mid-stream: the TCP
        // socket stays ESTABLISHED for ~60s while traffic is dead,
        // and every request riding it burns a 10s timeout. Detection
        // must be fast: interval 10s + timeout 12s → a dead conn is
        // closed after ~2 failed rounds (~40s) instead of ~90s.
        ping: ping::Behaviour::new(
            ping::Config::new()
                .with_interval(std::time::Duration::from_secs(10))
                .with_timeout(std::time::Duration::from_secs(12)),
        ),
        identify: identify::Behaviour::new(identify::Config::new(
            "/noid/1.0.0".into(),
            key.public(),
        )),
        kademlia,
        request_response,
        relay: relay::Behaviour::new(
            key.public().to_peer_id(),
            relay_behaviour_config,
        ),
        relay_client,
        dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
        autonat: autonat::Behaviour::new(
            key.public().to_peer_id(),
            autonat::Config {
                // Probe peers we are already connected to — in a small
                // self-hosted network there may be no other candidates.
                use_connected: true,
                ..Default::default()
            },
        ),
        // UPnP/NAT-PMP is a LAN socket path — off under `tor_only`.
        upnp: libp2p::swarm::behaviour::toggle::Toggle::from(
            direct_discovery.then(upnp::tokio::Behaviour::default),
        ),
        mailbox,
        hop,
        limits: libp2p::connection_limits::Behaviour::new(
            libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(32))
                .with_max_pending_outgoing(Some(64))
                .with_max_established_incoming(Some(150))
                .with_max_established_outgoing(Some(150))
                // 8: on CGNAT a conn stays dead-but-ESTABLISHED
                // until ping reaps it (~36s); the direct-upgrade +
                // relayed + reservation conns the fixed lifecycle
                // keeps alive need headroom over the zombie set so
                // a flap burst can never exhaust the per-peer cap
                // and deny the RESERVE conn a relay listener opens.
                .with_max_established_per_peer(Some(8)),
        ),
    })
}
