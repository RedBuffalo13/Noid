//! Availability regressions; all nodes and keys are isolated from user data.
use super::node::P2PNode;
use super::validating_store::ValidatingStore;
use crate::security::PrekeyBundle;
use libp2p::identity::Keypair;
use libp2p::kad::store::RecordStore;
use libp2p::kad::Record;
use libp2p::{Multiaddr, PeerId};
use std::time::{Duration, Instant};

fn signed_record(key: &Keypair, timestamp: &str) -> Record {
    let peer = key.public().to_peer_id().to_string();
    let mut bundle = PrekeyBundle {
        identity_public: vec![1; 32],
        signed_prekey_public: vec![2; 32],
        one_time_prekey_public: None,
        one_time_prekeys: vec![],
        owner_peer_id: Some(peer.clone()),
        identity_signature: None,
        generated_at: Some(timestamp.into()),
    };
    // Test-only fixtures must serialize and sign successfully.
    bundle.identity_signature = Some(crate::security::identity_sig::sign_payload(
        key,
        &crate::security::x3dh::prekey_signing_payload(&bundle),
    ).expect("fixture signature"));
    Record::new(
        P2PNode::prekey_dht_key(&peer),
        serde_json::to_vec(&bundle).expect("fixture JSON"),
    )
}

#[test]
fn identical_signed_put_retry_preserves_expiry_and_rejects_rollback() {
    let key = Keypair::generate_ed25519();
    let mut store = ValidatingStore::new(key.public().to_peer_id());
    let mut record = signed_record(&key, "2026-10-27T08:00:00Z");
    let expiry = Instant::now() + Duration::from_secs(60);
    record.expires = Some(expiry);
    store.put(record.clone()).expect("initial publication");
    let mut retry = record.clone();
    retry.expires = Some(expiry + Duration::from_secs(3600));
    assert!(store.put(retry).is_ok(), "network retry must pass local store");
    assert_eq!(store.get(&record.key).expect("stored record").expires, Some(expiry));
    assert!(store.put(signed_record(&key, "2026-10-27T07:00:00Z")).is_err());
    let mut forged = record.clone();
    forged.value.push(b'!');
    assert!(store.put(forged).is_err());
}

#[tokio::test]
async fn bootstrap_transient_failures_do_not_quarantine_seed() {
    let dir = tempfile::tempdir().expect("test directory");
    let mut node = P2PNode::new_relay(dir.path(), Some(0)).await.expect("test node");
    let peer = PeerId::random();
    let addr: Multiaddr = format!("/ip4/203.0.113.7/tcp/4020/p2p/{peer}")
        .parse().expect("fixture address");
    node.bootstrap_peers.push((peer, addr.clone()));
    for _ in 0..3 {
        node.note_dial_failure(&addr, false);
    }
    assert!(!node.is_dead_addr(&addr), "seed must recover without a 30-minute quarantine");
    node.bootstrap_retry_state.insert(peer.to_string(), (9, Instant::now()));
    node.retry_bootstrap_dials();
    let (_, next) = node.bootstrap_retry_state[&peer.to_string()];
    assert!(next <= Instant::now() + Duration::from_secs(60));
    assert!(node.swarm.behaviour_mut().kademlia.kbuckets().next().is_some(),
        "retry restores routing addresses removed by failure eviction");
    // WrongPeerId remains a hard refusal, not a transient outage.
    node.note_dial_failure(&addr, true);
    assert!(node.is_dead_addr(&addr));
}

#[tokio::test]
async fn blind_bootstrap_transient_failures_do_not_quarantine_seed() {
    let dir = tempfile::tempdir().expect("test directory");
    let mut node = P2PNode::new_relay(dir.path(), Some(0)).await.expect("test node");
    let addr: Multiaddr = "/ip4/203.0.113.7/tcp/4020".parse().expect("fixture address");
    node.blind_bootstrap_addrs.push(addr.clone());
    for _ in 0..3 {
        node.note_dial_failure(&addr, false);
    }
    assert!(!node.is_dead_addr(&addr), "blind seed must also remain retryable");
    node.retry_bootstrap_dials();
    assert!(node.bootstrap_retry_state.contains_key(&addr.to_string()),
        "blind-only configuration must not return before scheduling a retry");
}
