//! Temporary WAN probe: dial the public test server and report events.

use crate::p2p::node::P2PNode;
use crate::p2p::types::{P2PCommand, P2PEvent};
use libp2p::Multiaddr;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// Live-network probe — requires the VPS relay at 149.33.28.13:4020 to be
/// deployed and reachable. Run manually: `cargo test -- --ignored`.
#[tokio::test]
#[ignore]
async fn debug_dial_wan_server() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();
    let dir = tempdir().unwrap();
    let mut node = P2PNode::new(dir.path()).await.unwrap();
    let addr: Multiaddr = "/ip4/149.33.28.13/tcp/4020/p2p/12D3KooWPt6YBF4waTzfUSHZ963Mq2gaWYPFFkiKpUKYN1PK2SXu"
        .parse()
        .unwrap();
    node.swarm.dial(addr).unwrap();
    let (ev_tx, mut ev_rx) = mpsc::channel::<P2PEvent>(256);
    let (_cmd_tx, cmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { node.run(ev_tx, cmd_rx).await });

    let res = timeout(Duration::from_secs(60), async {
        while let Some(ev) = ev_rx.recv().await {
            let connected = matches!(ev, P2PEvent::PeerConnected(_));
            eprintln!("PROBE EVENT received (connected={})", connected);
            if connected {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(res, Ok(true), "no PeerConnected within 60s");
}

/// Full cold-start probe against the public seed: bootstrap → direct conn →
/// relay reservation → relayed listen addr. This is the exact path a fresh
/// GUI client walks after PIN entry.
/// Live-network probe — requires the VPS relay at 149.33.28.13:4020 to be
/// deployed and reachable. Run manually: `cargo test -- --ignored`.
#[tokio::test]
#[ignore]
async fn debug_wan_reservation_probe() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();
    let dir = tempdir().unwrap();
    let mut node = P2PNode::new(dir.path()).await.unwrap();
    let addr: Multiaddr = "/ip4/149.33.28.13/tcp/4020/p2p/12D3KooWPt6YBF4waTzfUSHZ963Mq2gaWYPFFkiKpUKYN1PK2SXu"
        .parse()
        .unwrap();
    node.bootstrap(vec![addr]).unwrap();
    let (ev_tx, mut ev_rx) = mpsc::channel::<P2PEvent>(256);
    let (_cmd_tx, cmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { node.run(ev_tx, cmd_rx).await });

    let res = timeout(Duration::from_secs(90), async {
        while let Some(ev) = ev_rx.recv().await {
            match &ev {
                P2PEvent::PeerConnected(p) => eprintln!("PROBE peer connected: {}", p),
                P2PEvent::PeerDisconnected(p) => eprintln!("PROBE peer disconnected: {}", p),
                P2PEvent::NewListenAddr(a) => eprintln!("PROBE listen addr: {}", a),
                P2PEvent::RelayStatusChanged { status } => {
                    eprintln!(
                        "PROBE status: peers={} known_relays={} reservations={} relayed={:?}",
                        status.peers_connected,
                        status.known_relays,
                        status.active_reservations,
                        status.relayed_addrs
                    );
                    if status.active_reservations > 0 && !status.relayed_addrs.is_empty() {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    })
    .await;
    assert_eq!(res, Ok(true), "no relay reservation within 90s");
}
