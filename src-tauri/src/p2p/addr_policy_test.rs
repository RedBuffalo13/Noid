use crate::p2p::addr_class::AddrClass;
use crate::p2p::classify_peer_addr::classify_peer_addr;
use crate::p2p::is_wan_cacheable::is_wan_cacheable;
use libp2p::{Multiaddr, PeerId};

fn addr(s: &str) -> Multiaddr {
    s.parse().unwrap()
}

#[test]
fn public_direct_classified() {
    let p = PeerId::random();
    let a = addr(&format!("/ip4/8.8.8.8/tcp/4001/p2p/{p}"));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::PublicDirect);
    assert!(is_wan_cacheable(&a, &p));
}

#[test]
fn lan_and_cgnat_are_lan() {
    let p = PeerId::random();
    for ip in [
        "10.0.0.5",
        "192.168.1.9",
        "172.16.3.4",
        "100.64.1.1",
        "169.254.1.1",
        "26.3.109.116", // Tele2 carrier-internal CGNAT space
        "25.10.0.4",    // UK-MoD range abused as CGNAT
    ] {
        let a = addr(&format!("/ip4/{ip}/tcp/4001/p2p/{p}"));
        assert_eq!(classify_peer_addr(&a, &p), AddrClass::Lan, "{ip}");
        assert!(is_wan_cacheable(&a, &p), "{ip}");
    }
}

#[test]
fn loopback_unspecified_are_local_not_cacheable() {
    let p = PeerId::random();
    for ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255"] {
        let a = addr(&format!("/ip4/{ip}/tcp/4001/p2p/{p}"));
        assert_eq!(classify_peer_addr(&a, &p), AddrClass::Local, "{ip}");
        assert!(!is_wan_cacheable(&a, &p), "{ip}");
    }
}

#[test]
fn valid_circuit_is_circuit_class() {
    let relay = PeerId::random();
    let p = PeerId::random();
    let a = addr(&format!(
        "/ip4/8.8.8.8/tcp/4010/p2p/{relay}/p2p-circuit/p2p/{p}"
    ));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::Circuit);
    assert!(is_wan_cacheable(&a, &p));
}

#[test]
fn nested_circuit_is_malformed() {
    let relay = PeerId::random();
    let p = PeerId::random();
    let a = addr(&format!(
        "/ip4/8.8.8.8/tcp/4010/p2p/{relay}/p2p-circuit/p2p/{relay}/p2p-circuit/p2p/{p}"
    ));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::Malformed);
    assert!(!is_wan_cacheable(&a, &p));
}

#[test]
fn foreign_terminal_peer_is_malformed() {
    let p = PeerId::random();
    let other = PeerId::random();
    let a = addr(&format!("/ip4/8.8.8.8/tcp/4001/p2p/{other}"));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::Malformed);
    assert!(!is_wan_cacheable(&a, &p));
}

#[test]
fn circuit_to_wrong_target_is_malformed() {
    let relay = PeerId::random();
    let p = PeerId::random();
    let other = PeerId::random();
    let a = addr(&format!(
        "/ip4/8.8.8.8/tcp/4010/p2p/{relay}/p2p-circuit/p2p/{other}"
    ));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::Malformed);
}

#[test]
fn no_transport_or_zero_port_is_malformed() {
    let p = PeerId::random();
    let bare = addr(&format!("/ip4/8.8.8.8/p2p/{p}"));
    assert_eq!(classify_peer_addr(&bare, &p), AddrClass::Malformed);
    let zero = addr(&format!("/ip4/8.8.8.8/tcp/0/p2p/{p}"));
    assert_eq!(classify_peer_addr(&zero, &p), AddrClass::Malformed);
}

#[test]
fn circuit_via_loopback_relay_is_malformed() {
    let relay = PeerId::random();
    let p = PeerId::random();
    let a = addr(&format!(
        "/ip4/127.0.0.1/tcp/4010/p2p/{relay}/p2p-circuit/p2p/{p}"
    ));
    assert_eq!(classify_peer_addr(&a, &p), AddrClass::Malformed);
    assert!(!is_wan_cacheable(&a, &p));
}
