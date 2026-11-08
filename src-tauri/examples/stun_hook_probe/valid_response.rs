#[test]
fn accepts_complete_aligned_response() {
    let response = crate::binding_response::binding_response(12);
    let expected = std::net::SocketAddr::from(([203, 0, 113, 7], 4020));
    assert_eq!(
        crate::stun_hook::parse_binding_response(&response, None),
        Some(expected)
    );
}
