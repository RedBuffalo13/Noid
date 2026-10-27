#[cfg(test)]
mod tests {
    use crate::p2p::types::{MessageType, NoidMessage};

    #[test]
    fn test_chat_message_serialization() {
        let msg = NoidMessage {
            sender: "alice_peer_id".to_string(),
            content: "Hello Bob!".to_string(),
            msg_type: MessageType::Chat("Hello Bob!".to_string()),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            id: "msg-123".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: NoidMessage = serde_json::from_str(&json).expect("Deserialization should work");

        assert_eq!(msg.sender, deserialized.sender);
        assert_eq!(msg.content, deserialized.content);
        assert_eq!(msg.id, deserialized.id);
    }

    #[test]
    fn test_contact_request_serialization() {
        let msg = NoidMessage {
            sender: "bob_peer_id".to_string(),
            content: "Hi, add me".to_string(),
            msg_type: MessageType::ContactRequest {
                message: "Hi, add me".to_string(),
                nickname: "Bob".to_string(),
                avatar: None,
            },
            timestamp: None,
            id: "req-456".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: NoidMessage = serde_json::from_str(&json).expect("Deserialization should work");

        match deserialized.msg_type {
            MessageType::ContactRequest { message, nickname, avatar } => {
                assert_eq!(message, "Hi, add me");
                assert_eq!(nickname, "Bob");
                assert!(avatar.is_none());
            }
            _ => panic!("Wrong msg_type after deserialization"),
        }
    }

    #[test]
    fn test_read_receipt_serialization() {
        let msg = NoidMessage {
            sender: "alice".to_string(),
            content: "msg-789".to_string(),
            msg_type: MessageType::ReadReceipt { message_id: "msg-789".to_string() },
            timestamp: Some("2024-01-01T12:00:00Z".to_string()),
            id: "receipt-001".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: NoidMessage = serde_json::from_str(&json).expect("Deserialization should work");

        match deserialized.msg_type {
            MessageType::ReadReceipt { message_id } => {
                assert_eq!(message_id, "msg-789");
            }
            _ => panic!("Wrong msg_type after deserialization"),
        }
    }

    #[test]
    fn test_typing_indicator_serialization() {
        let msg = NoidMessage {
            sender: "alice".to_string(),
            content: "typing".to_string(),
            msg_type: MessageType::TypingIndicator,
            timestamp: None,
            id: "typing-001".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: NoidMessage = serde_json::from_str(&json).expect("Deserialization should work");

        assert!(matches!(deserialized.msg_type, MessageType::TypingIndicator));
    }

    #[test]
    fn test_public_key_exchange_serialization() {
        let key = [42u8; 32];
        let msg = NoidMessage {
            sender: "alice".to_string(),
            content: String::new(),
            msg_type: MessageType::PublicKeyExchange { public_key: key },
            timestamp: None,
            id: "pk-001".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: NoidMessage = serde_json::from_str(&json).expect("Deserialization should work");

        match deserialized.msg_type {
            MessageType::PublicKeyExchange { public_key } => {
                assert_eq!(public_key, key);
            }
            _ => panic!("Wrong msg_type after deserialization"),
        }
    }
}
