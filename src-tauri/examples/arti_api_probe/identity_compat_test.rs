#[test]
fn legacy_and_current_peer_identity_are_compatible() -> anyhow::Result<()> {
    use libp2p::identity::Keypair;
    use libp2p_identity_legacy::Keypair as LegacyKeypair;
    use zeroize::Zeroizing;

    let legacy = LegacyKeypair::generate_ed25519();
    let mut encoded = Zeroizing::new(legacy.to_protobuf_encoding()?);
    let current = Keypair::from_protobuf_encoding(encoded.as_mut_slice())?;
    assert_eq!(legacy.public().to_peer_id().to_string(), current.public().to_peer_id().to_string());

    let payload = b"noid.identity.compatibility.v1";
    assert!(current.public().verify(payload, &legacy.sign(payload)?));
    assert!(legacy.public().verify(payload, &current.sign(payload)?));

    let mut rewritten = Zeroizing::new(current.to_protobuf_encoding()?);
    let reopened = LegacyKeypair::from_protobuf_encoding(rewritten.as_mut_slice())?;
    assert_eq!(legacy.public().to_peer_id().to_string(), reopened.public().to_peer_id().to_string());

    let fresh = Keypair::generate_ed25519();
    let mut fresh_encoded = Zeroizing::new(fresh.to_protobuf_encoding()?);
    let old_reader = LegacyKeypair::from_protobuf_encoding(fresh_encoded.as_mut_slice())?;
    assert_eq!(fresh.public().to_peer_id().to_string(), old_reader.public().to_peer_id().to_string());
    Ok(())
}
