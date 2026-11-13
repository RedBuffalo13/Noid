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

    // Optional onion transport + WebSocket/Secure-WebSocket transport —
    // registered while the builder is still in the transport phase
    // (before with_dns/relay). META-06: a single `websocket::Config` with
    // `tls::Config::client()` serves BOTH `/ws` and `/wss` multiaddrs —
    // `with_websocket` never sets a TLS config, so `/wss` dials (the
    // censorship-resistant :443 front) would otherwise fail outright.
    let builder = builder.with_other_transport(move |key| {
        use libp2p::core::transport::{OptionalTransport, Transport as _};

        let ws = ws_transport(key)?;
        let onion_opt = match onion_transport {
            Some(make) => OptionalTransport::some(make(key)?),
            None => OptionalTransport::none(),
        };
        Ok(ws
            .or_transport(onion_opt)
            .map(|either, _| either.into_inner())
            .boxed())
    })?;

    // DNS for the TCP/QUIC dial paths (IP-literal addrs pass through).
    // Android: hickory `Transport::system` needs /etc/resolv.conf — the
    // noid network dials IP literals only, so the phase is skipped; the
    // WSS inner transport above carries its own DoT resolver.
    #[cfg(not(target_os = "android"))]
    let builder = builder.with_dns()?;

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

/// Standalone WS/WSS transport over a DNS-resolving TCP inner — shared by
/// the main swarm (composed with the optional onion transport above) and
/// the ephemeral mailbox swarm. One `websocket::Config` with
/// `tls::Config::client()` serves BOTH `/ws` and `/wss` multiaddrs.
pub fn ws_transport(
    key: &libp2p::identity::Keypair,
) -> Result<
    libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::transport::{Boxed, Transport as _};
    use libp2p::core::upgrade::Version;

    type Err = Box<dyn std::error::Error + Send + Sync>;
    let tcp_t = libp2p::tcp::tokio::Transport::new(tcp::Config::default());
    // The WS inner transport must resolve `/dns4|6/` itself — the
    // outer `.with_dns()` phase only wraps the TCP/QUIC transports.
    #[cfg(not(target_os = "android"))]
    let dns_tcp = libp2p::dns::tokio::Transport::system(tcp_t)
        .map_err(|e| -> Err { e.to_string().into() })?;
    // Android has no /etc/resolv.conf — `Transport::system` fails at
    // swarm build. Cloudflare DoT (853) resolves without system conf
    // AND keeps DNS inside TLS, invisible to on-path inspection.
    #[cfg(target_os = "android")]
    let dns_tcp = libp2p::dns::tokio::Transport::custom(
        tcp_t,
        libp2p::dns::ResolverConfig::from_name_servers(
            hickory_resolver::config::CLOUDFLARE.tls().collect(),
        ),
        libp2p::dns::ResolverOpts::default(),
    );

    let mut ws_cfg = libp2p::websocket::Config::new(dns_tcp);
    ws_cfg.set_tls_config(libp2p::websocket::tls::Config::client());
    let ws: Boxed<(libp2p::PeerId, StreamMuxerBox)> = ws_cfg
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(p, m), _| (p, StreamMuxerBox::new(m)))
        .boxed();
    Ok(ws)
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
