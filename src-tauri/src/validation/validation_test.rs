use crate::validation::{bounded_str, parse_peer_id};

#[test]
fn parse_peer_id_accepts_valid() {
    let pid = libp2p::PeerId::random().to_string();
    assert!(parse_peer_id(&pid).is_ok());
}

#[test]
fn parse_peer_id_rejects_garbage() {
    assert!(parse_peer_id("").is_err());
    assert!(parse_peer_id("not-a-peer-id").is_err());
    assert!(parse_peer_id(&"x".repeat(300)).is_err());
}

#[test]
fn bounded_str_limits() {
    assert!(bounded_str("f", "ok", 10).is_ok());
    assert!(bounded_str("f", "", 10).is_err());
    assert!(bounded_str("f", &"a".repeat(11), 10).is_err());
    assert!(bounded_str("f", &"a".repeat(10), 10).is_ok());
}
