//! Swarm construction for the unified Noid node.
//!
//! Builds a [`Swarm<NoidBehaviour>`] with TCP + WebSocket transports,
//! Noise/Yamux, the circuit-relay *client* transport, and all behaviours
//! including the relay *server*, AutoNAT and UPnP.

use anyhow::Result;
use libp2p::{kad, noise, tcp, yamux, Swarm};
use std::time::Duration;

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::relay_config::RelayConfig;

/// Upgraded-transport factory: given the identity keypair, produce a boxed
/// transport yielding `(PeerId, StreamMuxerBox)` — the onion path supplies a
/// `TorTransport` upgraded through multistream/Noise/Yamux; ordinary callers
/// pass `None`.
pub type UpgradedTransportFactory = Box<
    dyn FnOnce(
            &libp2p::identity::Keypair,
        ) -> Result<
            libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>,
            Box<dyn std::error::Error + Send + Sync>,
        > + Send,
>;

/// Build the swarm from an identity keypair and the relay configuration.
/// `onion_transport`, when present, is registered as an additional transport
/// alongside TCP/QUIC/WS — used in `additional`/`tor_only` modes.
/// `direct_allowed == false` (tor_only effective policy) builds a swarm with
/// NO direct transports: only the onion transport + relay-client over it —
/// no TCP/QUIC/DNS/WS sockets, mDNS/UPnP behaviours off. The policy is
/// computed by the caller BEFORE this runs — a missing factory under
/// tor_only is a hard error, never a silent direct fallback.
pub async fn build_swarm(
    local_key: libp2p::identity::Keypair,
    relay_config: &RelayConfig,
    onion_transport: Option<UpgradedTransportFactory>,
    direct_allowed: bool,
    onion_relay_enabled: bool,
) -> Result<Swarm<NoidBehaviour>> {
    let relay_behaviour_config = if onion_relay_enabled {
        // P5: serve onion circuits only under the tight mobile budget.
        relay_config.to_onion_relay_config()
    } else {
        relay_config.to_libp2p_config()
    };

    if !direct_allowed {
        let Some(make) = onion_transport else {
            anyhow::bail!("tor_only requires a running Tor transport — no direct fallback");
        };
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(move |key| make(key))?
            .with_relay_client(
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(move |key, relay_client| {
                crate::p2p::build_behaviour::build_behaviour(
                    key, relay_client, relay_behaviour_config, false,
                )
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
            .build();
        force_kad_server(&mut swarm, relay_config);
        return Ok(swarm);
    }

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

    // Optional onion transport — must be registered while the builder is
    // still in the transport phase (before with_dns/with_websocket/relay).
    // OptionalTransport keeps a single phase type whether or not a factory
    // was supplied (or the feature exists).
    let builder = builder.with_other_transport(move |key| {
        use libp2p::core::transport::{Boxed, OptionalTransport};
        use libp2p::core::muxing::StreamMuxerBox;
        match onion_transport {
            Some(make) => make(key).map(OptionalTransport::some),
            None => Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                OptionalTransport::<Boxed<(libp2p::PeerId, StreamMuxerBox)>>::none(),
            ),
        }
    })?;

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
            let ws_transport = libp2p::websocket::Config::new(
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
        .with_behaviour(move |key, relay_client| {
            crate::p2p::build_behaviour::build_behaviour(
                key, relay_client, relay_behaviour_config, true,
            )
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    force_kad_server(&mut swarm, relay_config);
    Ok(swarm)
}

// Kademlia starts in Client mode and only promotes itself to Server
// once an external address is CONFIRMED (identify/AutoNAT dial-back).
// A dedicated relay behind NAT never receives that confirmation before
// it is well-known — nobody can dial it back through the firewall yet —
// so it would silently never answer DHT RPCs and every put_record /
// get_record in the network would time out. A Relay role or an
// operator-configured external_addr is an explicit reachability
// assertion: force Server mode.
fn force_kad_server(swarm: &mut Swarm<NoidBehaviour>, relay_config: &RelayConfig) {
    if relay_config.role == crate::p2p::NodeRole::Relay || relay_config.external_addr.is_some() {
        swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(kad::Mode::Server));
        log::info!("Kademlia forced to Server mode (relay role / external_addr configured)");
    }
}
