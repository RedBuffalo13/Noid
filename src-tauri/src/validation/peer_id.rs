/// Validate a peer id string arriving over the Tauri boundary.
/// An unparseable or absurdly long id must fail fast here — downstream code
/// (dialing, DHT keys, DB rows) assumes a well-formed `PeerId`.
pub fn parse_peer_id(input: &str) -> Result<libp2p::PeerId, String> {
    if input.is_empty() || input.len() > 128 {
        return Err("Invalid peer id length".into());
    }
    input
        .parse::<libp2p::PeerId>()
        .map_err(|_| "Invalid peer id".to_string())
}
