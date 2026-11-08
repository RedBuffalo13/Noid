#[test]
fn rejects_unaligned_declared_body() {
    let mut response = crate::binding_response::binding_response(13).to_vec();
    response.extend_from_slice(&[0u8; 4]);
    assert!(crate::stun_hook::parse_binding_response(&response, None).is_none());
}
