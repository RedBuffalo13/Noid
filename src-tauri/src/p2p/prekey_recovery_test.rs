//! Real transports: bootstrap recovery and signed prekey lookup without DHT routing.
use super::node::P2PNode;
use super::types::{P2PCommand, P2PEvent};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

async fn fetch_after_connect(
    mut rx: mpsc::Receiver<P2PEvent>,
    tx: &mpsc::Sender<P2PCommand>,
) -> crate::security::PrekeyBundle {
    let mut requested = false;
    timeout(Duration::from_secs(45), async {
        while let Some(event) = rx.recv().await {
            match event {
                P2PEvent::PeerConnected(peer) if !requested => {
                    requested = true;
                    tx.send(P2PCommand::FetchPrekeyBundle { peer_id: peer })
                        .await.expect("live command channel");
                }
                P2PEvent::PrekeyBundleRetrieved { peer_id, bundle } => {
                    let bundle = bundle.expect("must not report absence while direct path can answer");
                    assert_eq!(bundle.owner_peer_id.as_deref(), Some(peer_id.as_str()));
                    assert!(crate::security::x3dh::verify_prekey_bundle(&bundle));
                    return bundle;
                }
                _ => {}
            }
        }
        panic!("node stopped before answering");
    }).await.expect("signed prekey response within 45s")
}

#[tokio::test]
async fn direct_prekey_after_seed_outage_with_empty_routing_table() {
    let server_dir = tempfile::tempdir().expect("test directory");
    let client_dir = tempfile::tempdir().expect("test directory");
    let mut server = P2PNode::new_relay(server_dir.path(), Some(0)).await.expect("server");
    server.swarm.behaviour_mut().mdns = None.into();
    let peer = server.peer_id;
    let (bundle, _, _) = crate::security::x3dh::X3DH::new().generate_prekey_bundle();
    server.publish_prekey_bundle(&peer.to_string(), &bundle).expect("publish local bundle");
    let addr = timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.swarm.select_next_some().await {
                let text = address.to_string();
                if text.starts_with("/ip4/") && text.contains("/tcp/") && !text.contains("/ws") {
                    break text.replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/");
                }
            }
        }
    }).await.expect("server listener");
    let addr: Multiaddr = format!("{addr}/p2p/{peer}").parse().expect("listener address");
    let mut client = P2PNode::new_relay(client_dir.path(), Some(0)).await.expect("client");
    client.swarm.behaviour_mut().mdns = None.into();
    client.bootstrap_peers.push((peer, addr.clone()));
    for _ in 0..3 {
        client.note_dial_failure(&addr, false);
    }
    client.retry_bootstrap_dials();
    // Loopback is deliberately excluded from WAN Kademlia routing.
    assert_eq!(client.swarm.behaviour_mut().kademlia.kbuckets().count(), 0);
    let (server_tx, mut server_rx) = mpsc::channel(256);
    let (server_cmd, server_commands) = mpsc::channel(64);
    let server_task = tokio::spawn(server.run(server_tx, server_commands));
    let drain_task = tokio::spawn(async move { while server_rx.recv().await.is_some() {} });
    let (client_tx, client_rx) = mpsc::channel(256);
    let (client_cmd, client_commands) = mpsc::channel(64);
    let client_task = tokio::spawn(client.run(client_tx, client_commands));
    let received = fetch_after_connect(client_rx, &client_cmd).await;
    assert_eq!(received.identity_public, bundle.identity_public);
    client_cmd.send(P2PCommand::Shutdown).await.expect("stop client");
    server_cmd.send(P2PCommand::Shutdown).await.expect("stop server");
    client_task.await.expect("client task").expect("client shutdown");
    server_task.await.expect("server task").expect("server shutdown");
    drain_task.await.expect("event drain");
}

/// Uses a temporary identity; never opens client databases or sends chat content.
#[tokio::test]
#[ignore = "requires authorized network access to the configured VPS"]
async fn live_bootstrap_and_signed_prekey_recovery() {
    let dir = tempfile::tempdir().expect("test directory");
    let mut node = P2PNode::new_relay(dir.path(), Some(0)).await.expect("probe node");
    node.swarm.behaviour_mut().mdns = None.into();
    let seeds = super::load_bootstrap::load_bootstrap_nodes(dir.path());
    node.bootstrap(seeds).expect("configured bootstrap seeds");
    for (_, addr) in node.bootstrap_peers.clone() {
        for _ in 0..3 {
            node.note_dial_failure(&addr, false);
        }
    }
    node.retry_bootstrap_dials();
    let (event_tx, event_rx) = mpsc::channel(256);
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let task = tokio::spawn(node.run(event_tx, cmd_rx));
    let bundle = fetch_after_connect(event_rx, &cmd_tx).await;
    let peer: PeerId = bundle.owner_peer_id.expect("verified owner").parse().expect("valid peer");
    eprintln!("WAN recovery: verified signed prekey received (owner suffix {})",
        &peer.to_string()[peer.to_string().len() - 4..]);
    cmd_tx.send(P2PCommand::Shutdown).await.expect("stop probe");
    task.await.expect("probe task").expect("probe shutdown");
}
