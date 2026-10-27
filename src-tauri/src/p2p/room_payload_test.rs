#[cfg(test)]
mod tests {
    use crate::p2p::{MessageType, NoidMessage, RoomControlPayload, RoomInvitePayload, RoomPayload};

    #[test]
    fn room_payload_chat_roundtrip() {
        let p = RoomPayload::Chat { content: "hi room".into() };
        let json = serde_json::to_vec(&p).unwrap();
        let back: RoomPayload = serde_json::from_slice(&json).unwrap();
        match back {
            RoomPayload::Chat { content } => assert_eq!(content, "hi room"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn room_payload_meta_partial_fields() {
        let p = RoomPayload::Meta { name: Some("new name".into()), avatar: None };
        let back: RoomPayload = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        match back {
            RoomPayload::Meta { name, avatar } => {
                assert_eq!(name.as_deref(), Some("new name"));
                assert!(avatar.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn room_control_key_update_roundtrip() {
        let p = RoomControlPayload::KeyUpdate { epoch: 3, key: vec![7u8; 32] };
        let back: RoomControlPayload =
            serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        match back {
            RoomControlPayload::KeyUpdate { epoch, key } => {
                assert_eq!(epoch, 3);
                assert_eq!(key.len(), 32);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn room_control_all_variants_serialize() {
        for p in [
            RoomControlPayload::Removed { by: "peer".into() },
            RoomControlPayload::MemberLeft { peer_id: "peer".into() },
            RoomControlPayload::Meta { name: None, avatar: Some("data:image/x".into()), owner: None },
            RoomControlPayload::Meta { name: None, avatar: None, owner: Some("owner-peer".into()) },
            RoomControlPayload::Deleted,
            RoomControlPayload::KeySyncRequest { epoch: 1 },
        ] {
            let json = serde_json::to_vec(&p).unwrap();
            let _: RoomControlPayload = serde_json::from_slice(&json).unwrap();
        }
    }

    #[test]
    fn invite_payload_with_meta_roundtrip() {
        let p = RoomInvitePayload {
            key: vec![1u8; 32],
            name: Some("team".into()),
            avatar: None,
            owner: Some("owner-peer".into()),
            epoch: 2,
            members: vec![],
        };
        let back: RoomInvitePayload =
            serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(back.name.as_deref(), Some("team"));
        assert_eq!(back.epoch, 2);
        assert_eq!(back.key.len(), 32);
    }

    #[test]
    fn room_control_message_type_in_noid_message() {
        let msg = NoidMessage {
            sender: "owner".into(),
            content: String::new(),
            msg_type: MessageType::RoomControl {
                room_id: "room123".into(),
                wrapped_payload: vec![9u8; 64],
            },
            timestamp: None,
            id: "m1".into(),
        };
        // The pending-fallback path serializes the whole message under a
        // NOIDMSG1: marker — it must roundtrip losslessly.
        let body = format!("NOIDMSG1:{}", serde_json::to_string(&msg).unwrap());
        let back: NoidMessage =
            serde_json::from_str(body.strip_prefix("NOIDMSG1:").unwrap()).unwrap();
        match back.msg_type {
            MessageType::RoomControl { room_id, wrapped_payload } => {
                assert_eq!(room_id, "room123");
                assert_eq!(wrapped_payload.len(), 64);
            }
            _ => panic!("wrong msg_type"),
        }
    }

    #[test]
    fn room_chat_envelope_roundtrip_via_noidmsg() {
        // Offline room delivery: the sealed envelope bytes ride inside a
        // RoomChat message — the pending/mailbox fallback serializes the
        // whole NoidMessage under a NOIDMSG1: marker; it must roundtrip.
        let msg = NoidMessage {
            sender: "sender".into(),
            content: String::new(),
            msg_type: MessageType::RoomChat {
                room_id: "r1".into(),
                envelope: vec![7u8; 96],
            },
            timestamp: None,
            id: "m1".into(),
        };
        let body = format!("NOIDMSG1:{}", serde_json::to_string(&msg).unwrap());
        let back: NoidMessage =
            serde_json::from_str(body.strip_prefix("NOIDMSG1:").unwrap()).unwrap();
        match back.msg_type {
            MessageType::RoomChat { room_id, envelope } => {
                assert_eq!(room_id, "r1");
                assert_eq!(envelope.len(), 96);
            }
            _ => panic!("wrong msg_type"),
        }
    }

    #[test]
    fn legacy_plaintext_is_not_room_payload() {
        // Envelopes sealed by pre-payload clients carry raw UTF-8 text —
        // parsing must fail so receivers treat it as Chat, not error out.
        assert!(serde_json::from_slice::<RoomPayload>(b"hello room").is_err());
    }

    #[test]
    fn invite_offer_payload_never_carries_key() {
        // Two-phase invite, phase 1: the offer wire form must not contain
        // a `key` field — the room key is only delivered after acceptance.
        let p = crate::p2p::RoomInviteOfferPayload {
            name: Some("team".into()),
            avatar: Some("data:image/x".into()),
            owner: Some("owner".into()),
            epoch: 5,
            members: vec![],
        };
        let json: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("key"), "offer leaked a room key field");
        assert_eq!(obj["name"].as_str(), Some("team"));
        assert_eq!(obj["epoch"].as_u64(), Some(5));
        let back: crate::p2p::RoomInviteOfferPayload =
            serde_json::from_value(json).unwrap();
        assert_eq!(back.owner.as_deref(), Some("owner"));
    }

    #[test]
    fn room_invite_offer_accept_decline_roundtrip_via_noidmsg() {
        // The pending/mailbox fallback serializes the whole message under
        // a NOIDMSG1: marker — all three two-phase variants must survive.
        for mt in [
            MessageType::RoomInviteOffer {
                room_id: "r1".into(),
                wrapped_meta: vec![1u8; 48],
            },
            MessageType::RoomInviteAccept { room_id: "r1".into() },
            MessageType::RoomInviteDecline { room_id: "r1".into() },
        ] {
            let msg = NoidMessage {
                sender: "a".into(),
                content: String::new(),
                msg_type: mt,
                timestamp: None,
                id: "m".into(),
            };
            let body = format!("NOIDMSG1:{}", serde_json::to_string(&msg).unwrap());
            let back: NoidMessage =
                serde_json::from_str(body.strip_prefix("NOIDMSG1:").unwrap()).unwrap();
            match (&msg.msg_type, &back.msg_type) {
                (
                    MessageType::RoomInviteOffer { room_id, .. },
                    MessageType::RoomInviteOffer { room_id: r2, wrapped_meta },
                ) => {
                    assert_eq!(room_id, r2);
                    assert_eq!(wrapped_meta.len(), 48);
                }
                (MessageType::RoomInviteAccept { .. }, MessageType::RoomInviteAccept { .. }) => {}
                (MessageType::RoomInviteDecline { .. }, MessageType::RoomInviteDecline { .. }) => {}
                _ => panic!("variant changed across NOIDMSG1 roundtrip"),
            }
        }
    }

    #[test]
    fn invite_payload_roster_roundtrip() {
        // The key-delivery payload carries the inviter's roster so the
        // invitee can populate its member list immediately.
        let p = RoomInvitePayload {
            key: vec![3u8; 32],
            name: None,
            avatar: None,
            owner: Some("owner".into()),
            epoch: 0,
            members: vec![
                crate::p2p::RoomMemberProfile {
                    peer_id: "owner".into(),
                    name: Some("Alice".into()),
                    avatar: Some("data:image/x".into()),
                },
                crate::p2p::RoomMemberProfile {
                    peer_id: "member1".into(),
                    name: None,
                    avatar: None,
                },
            ],
        };
        let back: RoomInvitePayload =
            serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(back.members.len(), 2);
        assert_eq!(back.members[0].name.as_deref(), Some("Alice"));
        assert_eq!(back.members[1].peer_id, "member1");
    }

    #[test]
    fn member_profile_roundtrip() {
        for p in [
            RoomPayload::MemberJoined {
                peer_id: "p1".into(),
                name: Some("Bob".into()),
                avatar: None,
            },
            RoomPayload::MemberProfile {
                peer_id: "p1".into(),
                name: Some("Bob".into()),
                avatar: Some("data:image/x".into()),
            },
        ] {
            let back: RoomPayload =
                serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
            match (&p, &back) {
                (
                    RoomPayload::MemberJoined { peer_id, name, .. },
                    RoomPayload::MemberJoined {
                        peer_id: p2,
                        name: n2,
                        ..
                    },
                ) => {
                    assert_eq!(peer_id, p2);
                    assert_eq!(name, n2);
                }
                (
                    RoomPayload::MemberProfile { peer_id, .. },
                    RoomPayload::MemberProfile { peer_id: p2, .. },
                ) => assert_eq!(peer_id, p2),
                _ => panic!("variant changed across roundtrip"),
            }
        }
    }

    #[test]
    fn legacy_member_joined_without_profile_parses() {
        // Pre-profile MemberJoined envelopes carry only peer_id — the new
        // fields must default instead of failing the whole payload.
        let back: RoomPayload =
            serde_json::from_str(r#"{"t":"memberJoined","peer_id":"p1"}"#).unwrap();
        match back {
            RoomPayload::MemberJoined {
                peer_id,
                name,
                avatar,
            } => {
                assert_eq!(peer_id, "p1");
                assert!(name.is_none() && avatar.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn legacy_room_invite_still_roundtrips() {
        // Phase 2 key delivery keeps using the RoomInvite variant — its
        // wire form must stay compatible for both peers on the new build.
        let msg = NoidMessage {
            sender: "a".into(),
            content: String::new(),
            msg_type: MessageType::RoomInvite {
                room_id: "r1".into(),
                wrapped_key: vec![2u8; 64],
            },
            timestamp: None,
            id: "m".into(),
        };
        let body = format!("NOIDMSG1:{}", serde_json::to_string(&msg).unwrap());
        let back: NoidMessage =
            serde_json::from_str(body.strip_prefix("NOIDMSG1:").unwrap()).unwrap();
        match back.msg_type {
            MessageType::RoomInvite { room_id, wrapped_key } => {
                assert_eq!(room_id, "r1");
                assert_eq!(wrapped_key.len(), 64);
            }
            _ => panic!("wrong msg_type"),
        }
    }
}
