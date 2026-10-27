use noid_lib::p2p::types::{MessageType, NoidMessage};

#[test]
fn test_noid_message_round_trip_json() {
    let msg = NoidMessage {
        sender: "12D3KooWTestPeerId".to_string(),
        content: "Integration test message".to_string(),
        msg_type: MessageType::Chat("Integration test message".to_string()),
        timestamp: Some("2024-06-19T10:00:00Z".to_string()),
        id: "integration-001".to_string(),
    };

    let json = serde_json::to_string(&msg).expect("serialize");
    let decoded: NoidMessage = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(decoded.sender, msg.sender);
    assert_eq!(decoded.content, msg.content);
    assert_eq!(decoded.id, msg.id);
}

#[test]
fn test_dht_ack_message() {
    let msg = NoidMessage {
        sender: "peer_a".to_string(),
        content: "original-123".to_string(),
        msg_type: MessageType::DHTAck { original_message_id: "original-123".to_string() },
        timestamp: None,
        id: "ack-001".to_string(),
    };

    let json = serde_json::to_string(&msg).expect("serialize");
    let decoded: NoidMessage = serde_json::from_str(&json).expect("deserialize");

    match decoded.msg_type {
        MessageType::DHTAck { original_message_id } => {
            assert_eq!(original_message_id, "original-123");
        }
        _ => panic!("Expected DHTAck"),
    }
}

#[test]
fn test_file_offer_message() {
    let msg = NoidMessage {
        sender: "peer_b".to_string(),
        content: "file_offer".to_string(),
        msg_type: MessageType::FileOffer {
            name: "document.pdf".to_string(),
            size: 1024,
            id: "file-001".to_string(),
        },
        timestamp: Some("2024-06-19T11:00:00Z".to_string()),
        id: "offer-001".to_string(),
    };

    let json = serde_json::to_string(&msg).expect("serialize");
    let decoded: NoidMessage = serde_json::from_str(&json).expect("deserialize");

    match decoded.msg_type {
        MessageType::FileOffer { name, size, id } => {
            assert_eq!(name, "document.pdf");
            assert_eq!(size, 1024);
            assert_eq!(id, "file-001");
        }
        _ => panic!("Expected FileOffer"),
    }
}

#[test]
fn test_room_invite_message() {
    let msg = NoidMessage {
        sender: "peer_c".to_string(),
        content: "join room".to_string(),
        msg_type: MessageType::RoomInvite { room_id: "room-abc".to_string(), wrapped_key: vec![9, 9] },
        timestamp: None,
        id: "invite-001".to_string(),
    };

    let json = serde_json::to_string(&msg).expect("serialize");
    let decoded: NoidMessage = serde_json::from_str(&json).expect("deserialize");

    match decoded.msg_type {
        MessageType::RoomInvite { room_id, wrapped_key } => {
            assert_eq!(room_id, "room-abc");
            assert_eq!(wrapped_key, vec![9, 9]);
        }
        _ => panic!("Expected RoomInvite"),
    }
}
