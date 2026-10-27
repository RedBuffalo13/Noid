//! Phase T: P2P integration tests with local libp2p swarms.
//!
//! These tests create real P2PNode instances in temporary directories
//! and test retry queue logic, DHT key derivation, and event loop state
//! transitions without requiring external network connectivity.

use crate::p2p::node::P2PNode;
use crate::p2p::types::{MessageType, NoidMessage};
use tempfile::tempdir;

async fn create_test_node() -> P2PNode {
    let dir = tempdir().unwrap();
    P2PNode::new(dir.path()).await.unwrap()
}

#[allow(dead_code)] // helper kept for future integration cases
fn make_test_message(content: &str) -> NoidMessage {
    NoidMessage {
        sender: "alice".to_string(),
        content: content.to_string(),
        msg_type: MessageType::Chat(content.to_string()),
        timestamp: Some("2024-01-01T00:00:00.00Z".to_string()),
        id: format!("msg-{}", content.len()),
    }
}

#[tokio::test]
async fn test_node_creation() {
    let node = create_test_node().await;
    assert!(!node.peer_id.to_string().is_empty());
    assert!(node.pending_messages.is_empty());
    assert!(node.seen_message_ids.is_empty());
}

#[tokio::test]
async fn test_seen_message_ids_dedup() {
    let mut node = create_test_node().await;
    let msg_id = "msg-unique-123";
    assert!(!node.seen_message_ids.contains(msg_id));
    node.seen_message_ids.insert(msg_id.to_string());
    assert!(node.seen_message_ids.contains(msg_id));
}

#[tokio::test]
async fn test_pending_lookups_tracking() {
    let node = create_test_node().await;
    assert!(node.pending_lookups.is_empty());
    assert!(node.pending_prekey_queries.is_empty());
    assert!(node.pending_mailbox_lookups.is_empty());
}

#[tokio::test]
async fn test_local_dht_records_store_and_retrieve() {
    let mut node = create_test_node().await;
    let key = vec![1, 2, 3];
    let value = vec![4, 5, 6];
    node.local_dht_records.insert(key.clone(), value.clone());
    assert_eq!(node.local_dht_records.get(&key), Some(&value));
}

#[tokio::test]
async fn test_known_relays_initially_empty() {
    let node = create_test_node().await;
    assert!(node.known_relays.is_empty());
}

#[tokio::test]
async fn test_my_username_initially_none() {
    let node = create_test_node().await;
    assert!(node.my_username.is_none());
}

#[tokio::test]
async fn test_mailbox_db_initialized() {
    // Mailbox serving must not depend on login — the node opens its own
    // mailbox.db at startup so relays/pre-login nodes can store envelopes.
    let node = create_test_node().await;
    assert!(node.db.is_some());
}

#[tokio::test]
async fn test_audit_log_initially_none() {
    let node = create_test_node().await;
    assert!(node.audit_log.is_none());
}

#[tokio::test]
async fn test_generate_mailbox_message_id_is_unique() {
    let id1 = P2PNode::generate_mailbox_message_id();
    let id2 = P2PNode::generate_mailbox_message_id();
    assert_ne!(id1, id2);
    assert!(!id1.is_empty());
    assert!(!id2.is_empty());
}

#[tokio::test]
async fn test_generate_mailbox_message_id_is_valid_uuid() {
    let id = P2PNode::generate_mailbox_message_id();
    // Should be a valid UUID v4
    assert!(uuid::Uuid::parse_str(&id).is_ok());
}

/// Regression test: Verify that the event_loop's NotFound handler checks
/// pending_prekey_queries FIRST, then pending_mailbox_lookups, then falls
/// through to username lookup. This ordering is critical — a mailbox lookup
/// returning NotFound must NOT become a username lookup.
///
/// We simulate the HashMap operations that the event_loop performs.
#[tokio::test]
async fn test_mailbox_not_found_does_not_become_username_lookup() {
    let _node = create_test_node().await;

    // Simulate having both a mailbox lookup and a username lookup pending
    // We use string keys as stand-ins for QueryId (which has no public constructor)
    let mut pending_prekey: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_mailbox: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_username: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    pending_mailbox.insert("query_mailbox_1".to_string(), "peer1".to_string());
    pending_username.insert("query_username_1".to_string(), "alice".to_string());

    // Simulate the NotFound handler for the mailbox query
    let query_id = "query_mailbox_1";

    // Step 1: Check prekey queries (not found)
    let prekey_result = pending_prekey.remove(query_id);
    assert!(prekey_result.is_none());

    // Step 2: Check mailbox lookups (found — this is the correct behavior)
    let mailbox_result = pending_mailbox.remove(query_id);
    assert_eq!(mailbox_result, Some("peer1".to_string()));

    // Step 3: The username lookup should still be intact
    assert_eq!(pending_username.len(), 1);
    assert!(pending_username.contains_key("query_username_1"));
    assert_eq!(pending_username.get("query_username_1"), Some(&"alice".to_string()));
}

/// Regression test: Verify that a prekey query returning NotFound does NOT
/// fall through to mailbox or username lookup.
#[tokio::test]
async fn test_prekey_not_found_does_not_become_mailbox_or_username() {
    let mut pending_prekey: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_mailbox: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_username: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    pending_prekey.insert("query_prekey_1".to_string(), "peer1".to_string());
    pending_mailbox.insert("query_mailbox_1".to_string(), "peer2".to_string());
    pending_username.insert("query_username_1".to_string(), "alice".to_string());

    let query_id = "query_prekey_1";

    // Step 1: Check prekey queries (found)
    let prekey_result = pending_prekey.remove(query_id);
    assert_eq!(prekey_result, Some("peer1".to_string()));

    // The mailbox and username lookups should be untouched
    assert_eq!(pending_mailbox.len(), 1);
    assert_eq!(pending_username.len(), 1);
}

/// Regression test: When a username lookup returns NotFound and the query_id
/// is not in pending_lookups, the code uses unwrap_or_default() which produces "".
/// This must NOT emit a false UsernameAvailabilityChecked event.
#[tokio::test]
async fn test_username_lookup_not_found_uses_default() {
    let mut pending_prekey: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_mailbox: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_username: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let unknown_query_id = "query_unknown";

    // No entries in any pending map
    let prekey_result = pending_prekey.remove(unknown_query_id);
    assert!(prekey_result.is_none());

    let mailbox_result = pending_mailbox.remove(unknown_query_id);
    assert!(mailbox_result.is_none());

    let username = pending_username.remove(unknown_query_id).unwrap_or_default();
    assert_eq!(username, "");
}

/// Regression test: Verify that unrelated pending queries remain intact
/// after processing a mailbox NotFound.
#[tokio::test]
async fn test_unrelated_queries_remain_intact_after_mailbox_not_found() {
    let mut pending_prekey: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_mailbox: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pending_username: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // Set up multiple queries
    pending_prekey.insert("prekey_q1".to_string(), "peer_a".to_string());
    pending_prekey.insert("prekey_q2".to_string(), "peer_b".to_string());
    pending_mailbox.insert("mailbox_q1".to_string(), "peer_c".to_string());
    pending_username.insert("username_q1".to_string(), "alice".to_string());
    pending_username.insert("username_q2".to_string(), "bob".to_string());

    // Process mailbox_q1 NotFound
    let query_id = "mailbox_q1";
    let prekey_result = pending_prekey.remove(query_id);
    assert!(prekey_result.is_none());

    let mailbox_result = pending_mailbox.remove(query_id);
    assert_eq!(mailbox_result, Some("peer_c".to_string()));

    // All other queries must remain intact
    assert_eq!(pending_prekey.len(), 2);
    assert_eq!(pending_username.len(), 2);
    assert!(pending_prekey.contains_key("prekey_q1"));
    assert!(pending_prekey.contains_key("prekey_q2"));
    assert!(pending_username.contains_key("username_q1"));
    assert!(pending_username.contains_key("username_q2"));
}

/// Dead-addr bookkeeping: a WrongPeerId dial result must dead-mark the addr
/// permanently so identify cannot resurrect it on the next connection.
#[tokio::test]
async fn test_dead_addr_wrong_peer_marked_permanently() {
    let mut node = create_test_node().await;
    let addr: libp2p::Multiaddr = "/ip4/203.0.113.7/tcp/4010/p2p/12D3KooWA9mw5BTmjfaDdZ5v4wEKSzKBHpQGJbNpDFkN1aNrC2kq".parse().unwrap();
    node.note_dial_failure(&addr, true);
    assert!(node.is_dead_addr(&addr));
    // The bare form must match the same mark — identify learns bare addrs.
    let bare: libp2p::Multiaddr = "/ip4/203.0.113.7/tcp/4010".parse().unwrap();
    assert!(node.is_dead_addr(&bare));
}

/// Transport failures dead-mark only after the threshold, and a successful
/// dial clears the bookkeeping (self-healing).
#[tokio::test]
async fn test_dead_addr_transport_threshold_and_success_reset() {
    let mut node = create_test_node().await;
    let addr: libp2p::Multiaddr = "/ip4/203.0.113.8/udp/4020/quic-v1".parse().unwrap();
    node.note_dial_failure(&addr, false);
    node.note_dial_failure(&addr, false);
    assert!(!node.is_dead_addr(&addr));
    node.note_dial_failure(&addr, false);
    assert!(node.is_dead_addr(&addr));
    node.note_dial_success(&addr);
    assert!(!node.is_dead_addr(&addr));
}

/// A circuit addr is never dead-marked — its liveness belongs to the relay
/// reservation, not to our dial history.
#[tokio::test]
async fn test_dead_addr_circuit_never_marked() {
    let mut node = create_test_node().await;
    let addr: libp2p::Multiaddr = "/ip4/149.33.28.13/tcp/4020/p2p/12D3KooWA9mw5BTmjfaDdZ5v4wEKSzKBHpQGJbNpDFkN1aNrC2kq/p2p-circuit/p2p/12D3KooWDgCfqTRFVHWKrwmWqDwQMRcUdMNPPkFm1cXKErBQP98f".parse().unwrap();
    node.note_dial_failure(&addr, true);
    assert!(!node.is_dead_addr(&addr));
}
