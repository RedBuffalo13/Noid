//! Relay integration tests: real libp2p swarms exchanging reservations
//! and relayed connections, plus RelayConfig unit tests.

use crate::p2p::node::P2PNode;
use crate::p2p::relay_config::{NodeRole, PrivacyMode, RelayConfig};
use crate::p2p::relay_status::NatStatus;
use crate::p2p::types::{P2PCommand, P2PEvent};
use libp2p::Multiaddr;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

// ---------- RelayConfig unit tests ----------

#[test]
fn test_relay_config_defaults() {
    let cfg = RelayConfig::default();
    assert_eq!(cfg.role, NodeRole::Auto);
    assert_eq!(cfg.privacy, PrivacyMode::Direct);
    assert_eq!(cfg.listen_port, 4020);
    assert!(cfg.max_reservations > 0);
    assert!(cfg.max_circuits > 0);
}

#[test]
fn test_relay_config_save_load_roundtrip() {
    let dir = tempdir().unwrap();
    let cfg = RelayConfig {
        role: NodeRole::Relay,
        privacy: PrivacyMode::RelayedOnly,
        listen_port: 5555,
        ..RelayConfig::default()
    };
    cfg.save(dir.path()).unwrap();

    let loaded = RelayConfig::load(dir.path());
    assert_eq!(loaded.role, NodeRole::Relay);
    assert_eq!(loaded.privacy, PrivacyMode::RelayedOnly);
    assert_eq!(loaded.listen_port, 5555);
}

#[test]
fn test_relay_config_load_creates_default_file() {
    let dir = tempdir().unwrap();
    let cfg = RelayConfig::load(dir.path());
    assert_eq!(cfg.role, NodeRole::Auto);
    assert!(dir.path().join("relay_config.json").exists());
}

#[test]
fn test_relay_config_invalid_json_falls_back() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("relay_config.json"), "garbage").unwrap();
    let cfg = RelayConfig::load(dir.path());
    assert_eq!(cfg.role, NodeRole::Auto);
}

#[test]
fn test_client_role_zeroes_libp2p_limits() {
    let cfg = RelayConfig {
        role: NodeRole::Client,
        ..RelayConfig::default()
    };
    let lib_cfg = cfg.to_libp2p_config();
    assert_eq!(lib_cfg.max_reservations, 0);
    assert_eq!(lib_cfg.max_circuits, 0);
    assert_eq!(lib_cfg.max_reservations_per_peer, 0);
}

#[test]
fn test_relay_role_keeps_libp2p_limits() {
    let cfg = RelayConfig::default();
    let lib_cfg = cfg.to_libp2p_config();
    assert_eq!(lib_cfg.max_reservations, 128);
    assert_eq!(lib_cfg.max_circuits, 256);
    assert_eq!(lib_cfg.reservation_duration.as_secs(), 3600);
}

// ---------- should_relay / privacy helpers ----------

#[tokio::test]
async fn test_should_relay_roles() {
    // Relay role (forced by new_relay) always relays.
    let relay_dir = tempdir().unwrap();
    let relay = P2PNode::new_relay(relay_dir.path(), Some(0)).await.unwrap();
    assert!(relay.should_relay());
    drop(relay);

    // Client role never relays.
    let client_dir = tempdir().unwrap();
    RelayConfig {
        role: NodeRole::Client,
        ..RelayConfig::default()
    }
    .save(client_dir.path())
    .unwrap();
    let client = P2PNode::new(client_dir.path()).await.unwrap();
    assert!(!client.should_relay());
}

#[tokio::test]
async fn test_auto_role_not_relaying_when_unknown() {
    let dir = tempdir().unwrap();
    let mut node = P2PNode::new(dir.path()).await.unwrap();
    // Fresh node: nat_status = Unknown → Auto role does not relay yet.
    assert_eq!(node.nat_status, NatStatus::Unknown);
    assert!(!node.should_relay());
    // Once publicly reachable, Auto starts relaying.
    node.nat_status = NatStatus::Public;
    assert!(node.should_relay());
}

#[tokio::test]
async fn test_same_nat_foreign_addr_not_self() {
    // Two devices behind one NAT share the observed public IP. An addr
    // terminating at a *foreign* peer id must not be classified as our own
    // listen socket — previously the ip-only match dropped the sibling's
    // addr and same-NAT peers could never dial each other.
    use libp2p::multiaddr::Protocol;
    let dir = tempdir().unwrap();
    let mut node = P2PNode::new(dir.path()).await.unwrap();
    // Listeners register only once the swarm is polled — pump it until the
    // listen_on issued in with_config resolves into a bound listener.
    use libp2p::futures::StreamExt;
    for _ in 0..50 {
        if node.swarm.listeners().next().is_some() {
            break;
        }
        let _ = timeout(
            Duration::from_millis(100),
            node.swarm.select_next_some(),
        )
        .await;
    }
    // Bind the check to the node's real listener port so the test does not
    // depend on the fixed-port bind succeeding on the test host.
    let listen = node.swarm.listeners().next().unwrap().clone();
    let port = listen
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(v) => Some(v),
            _ => None,
        })
        .unwrap();
    node.external_addrs
        .push(format!("/ip4/203.0.113.7/tcp/{port}").parse().unwrap());

    // Foreign terminal id on our external ip:port → not self (same-NAT sibling).
    let foreign = libp2p::PeerId::random();
    let tagged: Multiaddr =
        format!("/ip4/203.0.113.7/tcp/{port}/p2p/{foreign}").parse().unwrap();
    assert!(!node.is_own_listen_addr(&tagged));

    // Foreign terminal id on loopback:port — also not self; if the addr is a
    // stale leak pointing at our own socket, the dial self-corrects via
    // WrongPeerId eviction instead of silently poisoning the address book.
    let tagged_loop: Multiaddr =
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{foreign}").parse().unwrap();
    assert!(!node.is_own_listen_addr(&tagged_loop));

    // Our own id on our own loopback socket is still self.
    let own_loop: Multiaddr =
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", node.peer_id)
            .parse()
            .unwrap();
    assert!(node.is_own_listen_addr(&own_loop));
}

#[tokio::test]
async fn test_dial_allowed_relayed_only() {
    let dir = tempdir().unwrap();
    RelayConfig {
        privacy: PrivacyMode::RelayedOnly,
        ..RelayConfig::default()
    }
    .save(dir.path())
    .unwrap();
    let node = P2PNode::new(dir.path()).await.unwrap();

    let circuit: Multiaddr = "/p2p-circuit/p2p/12D3KooWGRjTzCaDaR1XaWrK2qRkZcQvAL6bTQJZjJnmVVmJfS3k".parse().unwrap();
    let lan: Multiaddr = "/ip4/192.168.1.5/tcp/4001/p2p/12D3KooWGRjTzCaDaR1XaWrK2qRkZcQvAL6bTQJZjJnmVVmJfS3k".parse().unwrap();
    let wan: Multiaddr = "/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWGRjTzCaDaR1XaWrK2qRkZcQvAL6bTQJZjJnmVVmJfS3k".parse().unwrap();

    assert!(node.dial_allowed(&circuit));
    assert!(node.dial_allowed(&lan));
    assert!(!node.dial_allowed(&wan));
}

// ---------- End-to-end relay reservation + circuit ----------

/// Heavy e2e tests share the process: mDNS cross-discovers foreign test
/// nodes into each other's Kademlia tables and DHT provider records are
/// shared under `noid:relay-providers`. Serializing the swarm-level tests
/// keeps each test's network topology isolated.
static E2E_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Wait for a NewListenAddr event matching `pred`.
async fn wait_listen_addr(
    rx: &mut mpsc::Receiver<P2PEvent>,
    pred: impl Fn(&str) -> bool,
    secs: u64,
) -> Option<String> {
    timeout(Duration::from_secs(secs), async {
        while let Some(ev) = rx.recv().await {
            if let P2PEvent::NewListenAddr(addr) = &ev {
                if pred(addr) {
                    return Some(addr.clone());
                }
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Relay node accepts a reservation; client obtains a p2p-circuit listen addr.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // E2E_LOCK serializes port-bound tests intentionally
async fn test_relay_reservation_end_to_end() {
    let _e2e_guard = E2E_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).try_init();
    let relay_dir = tempdir().unwrap();
    let client_dir = tempdir().unwrap();

    // Relay node on an ephemeral port (test environment).
    let relay = P2PNode::new_relay(relay_dir.path(), Some(0)).await.unwrap();
    let relay_peer = relay.peer_id;
    let (rev_tx, mut rev_rx) = mpsc::channel::<P2PEvent>(64);
    let (rcmd_tx, rcmd_rx) = mpsc::channel::<P2PCommand>(64);
    let _rcmd_keep = rcmd_tx;
    tokio::spawn(async move { relay.run(rev_tx, rcmd_rx).await });

    // Get relay's TCP listen address.
    let relay_listen = wait_listen_addr(&mut rev_rx, |a| {
        a.starts_with("/ip4/") && a.contains("/tcp/") && !a.contains("p2p-circuit")
    }, 15)
    .await
    .expect("relay did not emit listen addr");
    // Replace 0.0.0.0 with 127.0.0.1 for dialing.
    let relay_base = relay_listen.replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/");
    let relay_base: Multiaddr = relay_base.parse().unwrap();

    // Client node — Client role so AutoNAT leaking in from the LAN
    // (a reachable-via-NAT-mapping verdict flips Auto nodes into relay
    // mode and skips reservations) cannot make the test env-dependent.
    let mut client = P2PNode::new(client_dir.path()).await.unwrap();
    client.relay_config.role = NodeRole::Client;
    let (cev_tx, mut cev_rx) = mpsc::channel::<P2PEvent>(64);
    let (ccmd_tx, ccmd_rx) = mpsc::channel::<P2PCommand>(64);
    let _ccmd_keep = ccmd_tx.clone();

    // Register the relay and dial it — the event loop requests the circuit
    // reservation on ConnectionEstablished (same path as bootstrap()).
    client.add_known_relay(relay_peer, vec![relay_base.clone()]);
    client.swarm.dial(
        relay_base.clone().with(libp2p::multiaddr::Protocol::P2p(relay_peer)),
    ).unwrap();
    tokio::spawn(async move { client.run(cev_tx, ccmd_rx).await });

    // Client should obtain a /p2p-circuit listen address.
    let circuit = wait_listen_addr(&mut cev_rx, |a| a.contains("p2p-circuit"), 20)
        .await;
    assert!(circuit.is_some(), "client never got a p2p-circuit listen addr");
    let circuit = circuit.unwrap();
    assert!(circuit.contains(&relay_peer.to_string()));
}

/// Two client nodes communicate through the relay via a relayed connection.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // E2E_LOCK serializes port-bound tests intentionally
async fn test_relayed_connection_between_peers() {
    let _e2e_guard = E2E_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).try_init();
    let relay_dir = tempdir().unwrap();
    let alice_dir = tempdir().unwrap();
    let bob_dir = tempdir().unwrap();

    let relay = P2PNode::new_relay(relay_dir.path(), Some(0)).await.unwrap();
    let relay_peer = relay.peer_id;
    let (rev_tx, mut rev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_r_tx, rcmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { relay.run(rev_tx, rcmd_rx).await });

    let relay_listen = wait_listen_addr(&mut rev_rx, |a| {
        a.starts_with("/ip4/") && a.contains("/tcp/") && !a.contains("p2p-circuit")
    }, 15)
    .await
    .expect("no relay listen addr");
    let relay_base: Multiaddr = relay_listen
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .parse()
        .unwrap();
    let relay_full = relay_base
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(relay_peer));

    // Alice: register relay + dial; event loop requests the reservation
    // once the direct connection is up. Client role — see note above.
    let mut alice = P2PNode::new(alice_dir.path()).await.unwrap();
    alice.relay_config.role = NodeRole::Client;
    let alice_peer = alice.peer_id;
    let (aev_tx, mut aev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_a_tx, acmd_rx) = mpsc::channel::<P2PCommand>(64);
    alice.add_known_relay(relay_peer, vec![relay_base.clone()]);
    alice.swarm.dial(relay_full.clone()).unwrap();
    tokio::spawn(async move { alice.run(aev_tx, acmd_rx).await });

    let alice_circuit = wait_listen_addr(&mut aev_rx, |a| a.contains("p2p-circuit"), 20)
        .await
        .expect("alice never got circuit addr");
    let alice_circuit_addr: Multiaddr = alice_circuit.parse().unwrap();

    // Bob: dial Alice through the relay using her circuit address.
    let mut bob = P2PNode::new(bob_dir.path()).await.unwrap();
    let (bev_tx, mut bev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_b_tx, bcmd_rx) = mpsc::channel::<P2PCommand>(64);
    // Dial through relay: {relay_base}/p2p/{relay}/p2p-circuit/p2p/{alice}
    // The reported listen addr may already terminate in /p2p/{alice} —
    // appending it again yields an undialable `…/p2p/X/p2p/X` addr.
    let dial_addr = match alice_circuit_addr.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(id)) if id == alice_peer => {
            alice_circuit_addr.clone()
        }
        _ => alice_circuit_addr
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(alice_peer)),
    };
    bob.swarm.dial(dial_addr).unwrap();
    tokio::spawn(async move { bob.run(bev_tx, bcmd_rx).await });

    // Bob should report a connection to Alice through the relay.
    let connected = timeout(Duration::from_secs(30), async {
        while let Some(ev) = bev_rx.recv().await {
            if let P2PEvent::PeerConnected(p) = ev {
                if p == alice_peer.to_string() {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    assert!(connected, "bob never connected to alice through the relay");
}

/// W2: a client that dials a relay-capable peer adopts it via Identify's
/// protocol list alone — no add_known_relay, no DHT provider record needed.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // E2E_LOCK serializes port-bound tests intentionally
async fn test_identify_autodetects_relay() {
    let _e2e_guard = E2E_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let relay_dir = tempdir().unwrap();
    let client_dir = tempdir().unwrap();

    let relay = P2PNode::new_relay(relay_dir.path(), Some(0)).await.unwrap();
    let relay_peer = relay.peer_id;
    let (rev_tx, mut rev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_r_tx, rcmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { relay.run(rev_tx, rcmd_rx).await });

    let relay_listen = wait_listen_addr(&mut rev_rx, |a| {
        a.starts_with("/ip4/") && a.contains("/tcp/") && !a.contains("p2p-circuit")
    }, 15)
    .await
    .expect("no relay listen addr");
    let relay_full: Multiaddr = relay_listen
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .parse::<Multiaddr>()
        .unwrap()
        .with(libp2p::multiaddr::Protocol::P2p(relay_peer));

    // Client dials blindly — it does NOT know this peer is a relay yet.
    // Client role — see note above.
    let mut client = P2PNode::new(client_dir.path()).await.unwrap();
    client.relay_config.role = NodeRole::Client;
    let (cev_tx, mut cev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_c_tx, ccmd_rx) = mpsc::channel::<P2PCommand>(64);
    client.swarm.dial(relay_full).unwrap();
    tokio::spawn(async move { client.run(cev_tx, ccmd_rx).await });

    // If identify-based detection works, the client requests a reservation
    // on its own and eventually gets a /p2p-circuit listen addr.
    let circuit = wait_listen_addr(&mut cev_rx, |a| a.contains("p2p-circuit"), 25)
        .await;
    assert!(
        circuit.is_some(),
        "client never reserved via identify-detected relay"
    );
    assert!(circuit.unwrap().contains(&relay_peer.to_string()));
}

/// W1 cold start: a fresh node reaches a peer purely from an invite string —
/// no bootstrap, no DHT entry, just `noid:<peer>@<relayed-addr>`.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // E2E_LOCK serializes port-bound tests intentionally
async fn test_cold_start_via_invite() {
    let _e2e_guard = E2E_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use crate::p2p::invite;
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).try_init();
    let relay_dir = tempdir().unwrap();
    let alice_dir = tempdir().unwrap();
    let bob_dir = tempdir().unwrap();

    let relay = P2PNode::new_relay(relay_dir.path(), Some(0)).await.unwrap();
    let relay_peer = relay.peer_id;
    let (rev_tx, mut rev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_r_tx, rcmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { relay.run(rev_tx, rcmd_rx).await });

    let relay_listen = wait_listen_addr(&mut rev_rx, |a| {
        a.starts_with("/ip4/") && a.contains("/tcp/") && !a.contains("p2p-circuit")
    }, 15)
    .await
    .expect("no relay listen addr");
    let relay_full: Multiaddr = relay_listen
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .parse::<Multiaddr>()
        .unwrap()
        .with(libp2p::multiaddr::Protocol::P2p(relay_peer));

    // Alice reserves a circuit on the relay (identify path also covered
    // here). Client role — see note above.
    let mut alice = P2PNode::new(alice_dir.path()).await.unwrap();
    alice.relay_config.role = NodeRole::Client;
    let alice_peer = alice.peer_id;
    let (aev_tx, mut aev_rx) = mpsc::channel::<P2PEvent>(64);
    let (_a_tx, acmd_rx) = mpsc::channel::<P2PCommand>(64);
    alice.swarm.dial(relay_full.clone()).unwrap();
    tokio::spawn(async move { alice.run(aev_tx, acmd_rx).await });

    let alice_circuit = wait_listen_addr(&mut aev_rx, |a| a.contains("p2p-circuit"), 25)
        .await
        .expect("alice never got circuit addr");

    // Alice builds an invite — build_invite appends her /p2p/ suffix.
    let invite_str = invite::build_invite(&alice_peer, &[alice_circuit]);
    let parsed = invite::parse_invite(&invite_str).expect("invite unparseable");
    assert_eq!(parsed.peer_id, alice_peer.to_string());
    assert_eq!(parsed.addrs.len(), 1);

    // Fresh Bob: no bootstrap, no relays — only the invite string.
    let bob = P2PNode::new(bob_dir.path()).await.unwrap();
    let (bev_tx, mut bev_rx) = mpsc::channel::<P2PEvent>(64);
    let (bcmd_tx, bcmd_rx) = mpsc::channel::<P2PCommand>(64);
    tokio::spawn(async move { bob.run(bev_tx, bcmd_rx).await });

    for addr in &parsed.addrs {
        bcmd_tx
            .send(P2PCommand::DialAddress { addr: addr.clone() })
            .await
            .unwrap();
    }

    let connected = timeout(Duration::from_secs(30), async {
        while let Some(ev) = bev_rx.recv().await {
            if let P2PEvent::PeerConnected(p) = ev {
                if p == alice_peer.to_string() {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    assert!(connected, "bob never reached alice via invite");
}
