/// Build a nonsecret protocol fixture with a controllable declared body length.
pub fn binding_response(body_length: u16) -> [u8; 32] {
    let mut response = [0u8; 32];
    response[..2].copy_from_slice(&[0x01, 0x01]);
    response[2..4].copy_from_slice(&body_length.to_be_bytes());
    response[4..8].copy_from_slice(&crate::stun_hook::STUN_MAGIC_COOKIE);
    response[20..26].copy_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
    let port = 4020u16 ^ 0x2112;
    response[26..28].copy_from_slice(&port.to_be_bytes());
    for (index, byte) in [203u8, 0, 113, 7].into_iter().enumerate() {
        response[28 + index] = byte ^ crate::stun_hook::STUN_MAGIC_COOKIE[index];
    }
    response
}
