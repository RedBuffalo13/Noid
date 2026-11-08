#[test]
fn rejects_response_with_truncated_declared_body() {
    let response = crate::binding_response::binding_response(16);
    assert!(crate::stun_hook::parse_binding_response(&response, None).is_none());
}
