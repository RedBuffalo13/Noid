#[test]
fn different_public_ips_are_not_a_cone_mapping() {
    use std::net::SocketAddr;
    let first = SocketAddr::from(([203, 0, 113, 1], 4020));
    let second = SocketAddr::from(([203, 0, 113, 2], 4020));
    let samples = [
        (SocketAddr::from(([127, 0, 0, 1], 3478)), first),
        (SocketAddr::from(([127, 0, 0, 1], 3479)), second),
    ];
    let result = crate::stun_hook::classify_stun_samples(&samples);
    assert!(!matches!(
        result,
        Some((_, crate::stun_hook::StunNatKind::Cone))
    ));
}
