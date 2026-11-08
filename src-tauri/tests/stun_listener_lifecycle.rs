#[tokio::test]
async fn closing_quic_listener_unregisters_its_stun_socket(
) -> Result<(), Box<dyn std::error::Error>> {
    use libp2p::core::transport::ListenerId;
    use libp2p::identity::Keypair;
    use libp2p::Transport;
    let key = Keypair::generate_ed25519();
    let mut transport = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(&key));
    let listener = ListenerId::next();
    transport.listen_on(listener, "/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    assert!(libp2p_quic::stun_hook::clone_listener_udp_socket(false).is_some());
    assert!(transport.remove_listener(listener));
    assert!(libp2p_quic::stun_hook::clone_listener_udp_socket(false).is_none());
    Ok(())
}
