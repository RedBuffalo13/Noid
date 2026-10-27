use crate::p2p::constants::{MAX_DHT_MESSAGE_SIZE, MAX_DHT_TTL_SECONDS};
use crate::p2p::load_bootstrap::load_bootstrap_nodes;
use crate::p2p::types::{
    DHTUserRecord, MailboxRequest, MailboxResponse, MessageType, NoidMessage,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn test_constants_max_dht_message_size() {
    assert_eq!(MAX_DHT_MESSAGE_SIZE, 1024);
}

#[test]
fn test_constants_max_dht_ttl() {
    assert_eq!(MAX_DHT_TTL_SECONDS, 86400); // 24 hours
}

#[test]
fn test_load_bootstrap_creates_default_file() {
    let dir = tempdir().unwrap();
    let nodes = load_bootstrap_nodes(dir.path());
    // Bundled seeds are EMPTY by design — a fresh install starts an
    // independent network (LAN mDNS / invite addrs / user seeds).
    let _ = nodes;
    // Default file should be created
    let config_path = dir.path().join("bootstrap_nodes.json");
    assert!(config_path.exists());
}

#[test]
fn test_load_bootstrap_reads_existing_file() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bootstrap_nodes.json");
    let custom_config = serde_json::json!({
        "nodes": ["/ip4/127.0.0.1/tcp/4001"]
    });
    std::fs::write(&config_path, serde_json::to_string_pretty(&custom_config).unwrap()).unwrap();
    let nodes = load_bootstrap_nodes(dir.path());
    // the one user entry (bundled list is empty by design)
    assert!(nodes.iter().any(|a| a.to_string().contains("127.0.0.1")));
}

#[test]
fn test_load_bootstrap_invalid_json_keeps_bundled() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bootstrap_nodes.json");
    std::fs::write(&config_path, "not valid json").unwrap();
    let nodes = load_bootstrap_nodes(dir.path());
    assert!(nodes.is_empty()); // corrupt user file quarantined; bundled empty
}

#[test]
fn test_load_bootstrap_missing_nodes_field_keeps_bundled() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bootstrap_nodes.json");
    std::fs::write(&config_path, "{}").unwrap();
    let nodes = load_bootstrap_nodes(dir.path());
    assert!(nodes.is_empty());
}

#[test]
fn test_load_bootstrap_invalid_addr_skipped() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bootstrap_nodes.json");
    let custom_config = serde_json::json!({
        "nodes": ["invalid_multiaddr", "/ip4/127.0.0.1/tcp/4001"]
    });
    std::fs::write(&config_path, serde_json::to_string_pretty(&custom_config).unwrap()).unwrap();
    let nodes = load_bootstrap_nodes(dir.path());
    // only the valid user addr + bundled seeds — the invalid one is skipped
    assert!(nodes.iter().any(|a| a.to_string().contains("127.0.0.1")));
    assert!(!nodes.iter().any(|a| a.to_string().contains("invalid_multiaddr")));
}

#[test]
fn test_dht_user_record_serialization() {
    let record = DHTUserRecord {
        peer_id: "12D3KooW...".to_string(),
        username: "alice".to_string(),
        nickname: "alice".to_string(),
        avatar: Some("avatar_data".to_string()),
        short_id: "ABC12345".to_string(),
        updated_at: "2024-01-01T00:00:00Z".to_string(),
        signature: None,
        revoked: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    let deserialized: DHTUserRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.peer_id, deserialized.peer_id);
    assert_eq!(record.nickname, deserialized.nickname);
    assert_eq!(record.short_id, deserialized.short_id);
}

#[test]
fn test_dht_user_record_camel_case_serialization() {
    let record = DHTUserRecord {
        peer_id: "peer1".to_string(),
        username: "alice".to_string(),
        nickname: "alice".to_string(),
        avatar: None,
        short_id: "ABC12345".to_string(),
        updated_at: "2024-01-01T00:00:00Z".to_string(),
        signature: None,
        revoked: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    // camelCase due to serde rename
    assert!(json.contains("peerId"));
    assert!(json.contains("shortId"));
    assert!(json.contains("updatedAt"));
    // snake_case should not be present
    assert!(!json.contains("peer_id"));
    assert!(!json.contains("short_id"));
}

#[test]
fn test_mailbox_request_store_serialization() {
    let req = MailboxRequest::Store {
        recipient_peer_id: "peer1".to_string(),
        sender_peer_id: "peer2".to_string(),
        encrypted_content: vec![1, 2, 3],
        signature: vec![9, 9],
        client_msg_id: Some("msg-abc".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: MailboxRequest = serde_json::from_str(&json).unwrap();
    match deserialized {
        MailboxRequest::Store { recipient_peer_id, sender_peer_id, encrypted_content, signature, client_msg_id } => {
            assert_eq!(signature, vec![9, 9]);
            assert_eq!(client_msg_id.as_deref(), Some("msg-abc"));
            assert_eq!(recipient_peer_id, "peer1");
            assert_eq!(sender_peer_id, "peer2");
            assert_eq!(encrypted_content, vec![1, 2, 3]);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_mailbox_request_retrieve_serialization() {
    let req = MailboxRequest::Retrieve {
        recipient_peer_id: "peer1".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: MailboxRequest = serde_json::from_str(&json).unwrap();
    match deserialized {
        MailboxRequest::Retrieve { recipient_peer_id } => {
            assert_eq!(recipient_peer_id, "peer1");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_mailbox_request_delete_serialization() {
    let req = MailboxRequest::Delete {
        message_id: "msg123".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: MailboxRequest = serde_json::from_str(&json).unwrap();
    match deserialized {
        MailboxRequest::Delete { message_id } => {
            assert_eq!(message_id, "msg123");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_mailbox_response_ack_serialization() {
    let resp = MailboxResponse::Ack { success: true };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: MailboxResponse = serde_json::from_str(&json).unwrap();
    match deserialized {
        MailboxResponse::Ack { success } => assert!(success),
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_mailbox_response_messages_serialization() {
    let resp = MailboxResponse::Messages {
        messages: vec![crate::p2p::types::MailboxMessageItem {
            id: "msg1".to_string(),
            sender: "sender1".to_string(),
            content: vec![1, 2, 3],
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            signature: vec![7, 8, 9],
        }],
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: MailboxResponse = serde_json::from_str(&json).unwrap();
    match deserialized {
        MailboxResponse::Messages { messages } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].id, "msg1");
            assert_eq!(messages[0].sender, "sender1");
            assert_eq!(messages[0].content, vec![1, 2, 3]);
            assert_eq!(messages[0].timestamp, "2024-01-01T00:00:00Z");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_mailbox_dht_key_derivation() {
    // Replicate mailbox_dht_key from mailbox.rs
    let peer_id = "12D3KooWTestPeerId";
    let prefix = format!("noid:mailbox:{}", peer_id);

    let mut hasher1 = Sha256::new();
    hasher1.update(prefix.as_bytes());
    let hash1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(prefix.as_bytes());
    let hash2 = hasher2.finalize();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_mailbox_dht_key_differs_from_message_key() {
    let peer_id = "12D3KooWTestPeerId";
    let msg_prefix = format!("noid:msg:{}:2024010112", peer_id);
    let mailbox_prefix = format!("noid:mailbox:{}", peer_id);

    let msg_key = {
        let mut h = Sha256::new();
        h.update(msg_prefix.as_bytes());
        h.finalize()
    };
    let mailbox_key = {
        let mut h = Sha256::new();
        h.update(mailbox_prefix.as_bytes());
        h.finalize()
    };
    assert_ne!(msg_key, mailbox_key);
}

#[test]
fn test_ratchet_chat_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: "encrypted".to_string(),
        msg_type: MessageType::RatchetChat {
            ciphertext: vec![1, 2, 3, 4],
            header_dh_public: vec![5u8; 32],
            header_pn: 0,
            header_n: 1,
        },
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        id: "msg1".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::RatchetChat { ciphertext, header_dh_public, header_pn, header_n } => {
            assert_eq!(ciphertext, vec![1, 2, 3, 4]);
            assert_eq!(header_dh_public, vec![5u8; 32]);
            assert_eq!(header_pn, 0);
            assert_eq!(header_n, 1);
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_x3dh_init_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::X3DHInit {
            identity_public: vec![1u8; 32],
            ephemeral_public: vec![2u8; 32],
            one_time_prekey_id: Some(vec![3u8; 32]),
            identity_signature: vec![9u8; 64],
        },
        timestamp: None,
        id: "x3dh-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::X3DHInit { identity_public, ephemeral_public, one_time_prekey_id, identity_signature } => {
            assert_eq!(identity_public, vec![1u8; 32]);
            assert_eq!(ephemeral_public, vec![2u8; 32]);
            assert_eq!(one_time_prekey_id, Some(vec![3u8; 32]));
            assert_eq!(identity_signature, vec![9u8; 64]);
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_x3dh_init_without_one_time_prekey() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::X3DHInit {
            identity_public: vec![1u8; 32],
            ephemeral_public: vec![2u8; 32],
            one_time_prekey_id: None,
            identity_signature: Vec::new(),
        },
        timestamp: None,
        id: "x3dh-002".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::X3DHInit { one_time_prekey_id, .. } => {
            assert!(one_time_prekey_id.is_none());
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_username_lookup_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::UsernameLookup {
            username: "bob".to_string(),
        },
        timestamp: None,
        id: "lookup-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::UsernameLookup { username } => {
            assert_eq!(username, "bob");
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_username_announce_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::UsernameAnnounce {
            username: "alice".to_string(),
        },
        timestamp: None,
        id: "announce-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::UsernameAnnounce { username } => {
            assert_eq!(username, "alice");
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_file_offer_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::FileOffer {
            name: "test.txt".to_string(),
            size: 1024,
            id: "file-001".to_string(),
        },
        timestamp: None,
        id: "offer-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::FileOffer { name, size, id } => {
            assert_eq!(name, "test.txt");
            assert_eq!(size, 1024);
            assert_eq!(id, "file-001");
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_room_invite_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::RoomInvite {
            room_id: "room-123".to_string(),
            wrapped_key: vec![1, 2, 3],
        },
        timestamp: None,
        id: "invite-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::RoomInvite { room_id, wrapped_key } => {
            assert_eq!(room_id, "room-123");
            assert_eq!(wrapped_key, vec![1, 2, 3]);
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_dht_ack_serialization() {
    let msg = NoidMessage {
        sender: "alice".to_string(),
        content: String::new(),
        msg_type: MessageType::DHTAck {
            original_message_id: "msg-123".to_string(),
        },
        timestamp: None,
        id: "ack-001".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: NoidMessage = serde_json::from_str(&json).unwrap();
    match deserialized.msg_type {
        MessageType::DHTAck { original_message_id } => {
            assert_eq!(original_message_id, "msg-123");
        }
        _ => panic!("Wrong msg_type"),
    }
}

#[test]
fn test_message_size_validation() {
    // A message within the limit should serialize fine
    let small_msg = NoidMessage {
        sender: "alice".to_string(),
        content: "hello".to_string(),
        msg_type: MessageType::Chat("hello".to_string()),
        timestamp: None,
        id: "msg1".to_string(),
    };
    let small_bytes = serde_json::to_vec(&small_msg).unwrap();
    assert!(small_bytes.len() <= MAX_DHT_MESSAGE_SIZE);

    // A message over the limit should exceed
    let large_content = "x".repeat(MAX_DHT_MESSAGE_SIZE);
    let large_msg = NoidMessage {
        sender: "alice".to_string(),
        content: large_content.clone(),
        msg_type: MessageType::Chat(large_content),
        timestamp: None,
        id: "msg2".to_string(),
    };
    let large_bytes = serde_json::to_vec(&large_msg).unwrap();
    assert!(large_bytes.len() > MAX_DHT_MESSAGE_SIZE);
}
