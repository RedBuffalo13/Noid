//! Temporary diagnostic: dial a libp2p node and print its real PeerId.
//! Usage: cargo run --example probe_relay -- /ip4/1.2.3.4/tcp/4010
use futures::StreamExt;
use libp2p::{multiaddr::Protocol, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr};
use std::time::Duration;

#[derive(NetworkBehaviour)]
struct ProbeBehaviour {
    identify: libp2p::identify::Behaviour,
    relay: libp2p::relay::client::Behaviour,
    ping: libp2p::ping::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::env::args().nth(1).expect("usage: probe_relay <multiaddr>");
    println!("arg = {raw:?}");
    let addr: Multiaddr = match raw.parse() {
        Ok(a) => a,
        Err(e) => {
            println!("PARSE ERR: {e:?}");
            return Err(e.into());
        }
    };

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()
        .expect("dns")
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await
        .expect("ws")
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .expect("relay client")
        .with_behaviour(|key, relay| {
            ProbeBehaviour {
                identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                    "/noid/probe".to_string(),
                    key.public(),
                )),
                relay,
                ping: libp2p::ping::Behaviour::new(
                    libp2p::ping::Config::new()
                        .with_interval(Duration::from_secs(5))
                        .with_timeout(Duration::from_secs(15)),
                ),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
        .build();

    swarm.dial(addr)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while let Some(ev) = swarm.next().await {
        match ev {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                println!("CONNECTED: {peer_id} (total {num_established})");
                let mut base = endpoint.get_remote_address().clone();
                // strip /p2p/<id> then re-add for the circuit addr
                while matches!(base.iter().last(), Some(Protocol::P2p(_))) {
                    base.pop();
                }
                let listen = base.with(Protocol::P2p(peer_id)).with(Protocol::P2pCircuit);
                println!("REQUESTING RESERVE via {listen}");
                match swarm.listen_on(listen) {
                    Ok(_) => println!("listen_on ok"),
                    Err(e) => println!("listen_on ERR: {e}"),
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("RESERVE ACCEPTED — circuit addr: {address}");
            }
            SwarmEvent::ListenerError { error, .. } => {
                println!("RESERVE FAILED: {error}");
            }
            SwarmEvent::Behaviour(ProbeBehaviourEvent::Identify(
                libp2p::identify::Event::Received { info, .. },
            )) => {
                println!("IDENTIFY agent={}", info.agent_version);
                for p in &info.protocols {
                    println!("  proto: {p}");
                }
            }
            SwarmEvent::Behaviour(ProbeBehaviourEvent::Relay(ev)) => {
                println!("RELAY EVENT: {ev:?}");
            }
            SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(ev)) => {
                match &ev.result {
                    Ok(rtt) => println!("PING ok: peer={} rtt={:?}", ev.peer, rtt),
                    Err(e) => println!("PING FAIL: peer={} err={:?}", ev.peer, e),
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                println!("CLOSED: {peer_id} (left {num_established}) cause={cause:?}");
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                println!("DIAL ERROR: {error}");
            }
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            println!("30s elapsed — done");
            return Ok(());
        }
    }
    Ok(())
}
