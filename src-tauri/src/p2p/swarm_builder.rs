//! Swarm construction for the unified Noid node.
//!
//! Builds a [`Swarm<NoidBehaviour>`] with TCP + WebSocket transports,
//! Noise/Yamux, the circuit-relay *client* transport, and all behaviours
//! including the relay *server*, AutoNAT and UPnP.

use anyhow::{anyhow, Result};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, ping, relay, request_response, tcp,
    upnp, yamux, Swarm,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::relay_config::RelayConfig;

/// Build the swarm from an identity keypair and the relay configuration.
pub async fn build_swarm(
    local_key: libp2p::identity::Keypair,
    relay_config: &RelayConfig,
) -> Result<Swarm<NoidBehaviour>> {
    let relay_behaviour_config = relay_config.to_libp2p_config();

    let builder = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        // QUIC (UDP) transport. Mobile CGNATs rebind/expire TCP NAT
        // mappings mid-flow — observed on Tele2: a conn completes the noise
        // handshake, then inbound packets vanish into a dead mapping
        // ~30-60s later while the local socket still reports ESTABLISHED.
        // QUIC survives NAT rebinding via connection IDs — the conn
        // migrates instead of dying.
        .with_quic_config(|mut cfg| {
            // Default idle timeout (10s) is too tight for carrier NAT
            // rebinding: while the mapping is being rebuilt inbound stalls,
            // and a 10s window kills the conn before migration completes.
            cfg.max_idle_timeout = 30_000;
            cfg
        });

    // Non-Android: standard DNS + WebSocket phases.
    #[cfg(not(target_os = "android"))]
    let builder = builder
        .with_dns()?
        .with_websocket(
            noise::Config::new,
            yamux::Config::default,
        )
        .await?;

    // Android: libp2p's `with_websocket` unconditionally wraps the WS-side TCP
    // in `libp2p_dns::tokio::Transport::system`, which reads the system
    // resolver config via hickory. Android has no /etc/resolv.conf, so swarm
    // construction fails with `WebsocketErrorInner::Dns` ("Dns") regardless
    // of `with_dns`/`without_dns`. Build the equivalent TCP+WebSocket
    // transports manually, without the DNS wrapper — the noid network only
    // ever dials IP-literal multiaddrs (bootstrap nodes, invite addrs, DHT
    // records and relay addresses are all numeric).
    #[cfg(target_os = "android")]
    let builder = builder.with_other_transport(
        |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
            use libp2p::core::{
                muxing::StreamMuxerBox, transport::Transport as _, upgrade::Version,
            };

            // TR-03: plain TCP is already registered by `.with_tcp` above —
            // only the WebSocket transport is built here. The previous
            // `ws.or_transport(tcp)` registered a SECOND TCP instance and
            // doubled every TCP listener/dial on Android.
            let ws_transport = libp2p::websocket::WsConfig::new(
                libp2p::tcp::tokio::Transport::new(tcp::Config::default()),
            )
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(key)?)
            .multiplex(yamux::Config::default())
            .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            Ok(ws_transport)
        },
    )?;

    let mut swarm = builder
        .with_relay_client(
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key, relay_client| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|msg| anyhow!("Gossipsub config error: {msg}"))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            // mDNS joins a multicast group, which can fail on restricted
            // platforms (Android without a held multicast lock, containers).
            // It is LAN discovery only — degrade gracefully instead of
            // failing the whole swarm build.
            let mdns = libp2p::swarm::behaviour::toggle::Toggle::from(
                match mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                ) {
                    Ok(behaviour) => Some(behaviour),
                    Err(e) => {
                        log::warn!("mDNS unavailable, LAN discovery disabled: {}", e);
                        None
                    }
                },
            );

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
                // resend storms. 30s matches the parked-ack sweep TTL.
                request_response::Config::default()
                    .with_request_timeout(std::time::Duration::from_secs(30)),
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
                upnp: upnp::tokio::Behaviour::default(),
                mailbox,
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
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    // Kademlia starts in Client mode and only promotes itself to Server
    // once an external address is CONFIRMED (identify/AutoNAT dial-back).
    // A dedicated relay behind NAT never receives that confirmation before
    // it is well-known — nobody can dial it back through the firewall yet —
    // so it would silently never answer DHT RPCs and every put_record /
    // get_record in the network would time out. A Relay role or an
    // operator-configured external_addr is an explicit reachability
    // assertion: force Server mode.
    if relay_config.role == crate::p2p::NodeRole::Relay || relay_config.external_addr.is_some() {
        swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(kad::Mode::Server));
        log::info!("Kademlia forced to Server mode (relay role / external_addr configured)");
    }

    Ok(swarm)
}
