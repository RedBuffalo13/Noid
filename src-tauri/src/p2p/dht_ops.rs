use anyhow::Result;

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Subscribe to an encrypted room topic. Requires the room key — a peer
    /// that only knows the room id can subscribe but never decrypt or
    /// produce valid envelopes, so joining without a key is rejected here.
    pub fn join_room(&mut self, room_id: &str, room_key: Option<[u8; 32]>) -> Result<()> {
        let Some(key) = room_key else {
            return Err(anyhow::anyhow!(
                "join_room requires the room key — join happens only via a ratchet-encrypted invite"
            ));
        };
        self.room_keys.insert(room_id.to_string(), key);
        let topic = libp2p::gossipsub::IdentTopic::new(Self::room_topic(room_id));
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        Ok(())
    }

    /// Publish a sealed, signed `RoomEnvelope` — plaintext never reaches
    /// gossipsub (only AES-256-GCM ciphertext + Ed25519 signature).
    /// The plaintext is a serialized `RoomPayload::Chat`; receivers that
    /// predate typed envelopes treat unparseable plaintext as chat text.
    pub fn send_room_message(&mut self, room_id: &str, content: &str) -> Result<()> {
        self.send_room_payload(room_id, &crate::p2p::RoomPayload::Chat {
            content: content.to_string(),
        })
    }

    /// Seal a `RoomPayload::Chat`, publish it to the room topic
    /// (best-effort — `InsufficientPeers` is tolerated because the caller
    /// fans the envelope out to members directly), and return the
    /// serialized envelope bytes for `MessageType::RoomChat` fan-out.
    pub fn send_room_chat_envelope(&mut self, room_id: &str, content: &str) -> Result<Vec<u8>> {
        let key = self
            .room_keys
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("not a member of room {}", room_id))?;
        let plaintext = serde_json::to_vec(&crate::p2p::RoomPayload::Chat {
            content: content.to_string(),
        })?;
        let msg_id = uuid::Uuid::new_v4().to_string();
        let env = crate::security::room_crypto::seal(
            key,
            room_id,
            &self.identity_keypair,
            &msg_id,
            &plaintext,
        )?;
        let data = serde_json::to_vec(&env)?;
        let topic = libp2p::gossipsub::IdentTopic::new(Self::room_topic(room_id));
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data.clone()) {
            log::debug!("Room {} topic publish skipped ({}), fan-out covers", room_id, e);
        }
        Ok(data)
    }

    /// Publish an arbitrary room payload as a sealed, signed envelope.
    /// Payloads carrying a data-URL avatar can exceed the gossipsub
    /// transmit limit — on `MessageTooLarge` we re-seal the payload with
    /// the avatar stripped so the announce (name at minimum) still lands.
    pub fn send_room_payload(
        &mut self,
        room_id: &str,
        payload: &crate::p2p::RoomPayload,
    ) -> Result<()> {
        let key = self
            .room_keys
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("not a member of room {}", room_id))?;
        let topic = libp2p::gossipsub::IdentTopic::new(Self::room_topic(room_id));

        for candidate in [Some(payload.clone()), Self::room_payload_slim(payload)]
            .into_iter()
            .flatten()
        {
            let plaintext = serde_json::to_vec(&candidate)?;
            let msg_id = uuid::Uuid::new_v4().to_string();
            let env = crate::security::room_crypto::seal(
                key,
                room_id,
                &self.identity_keypair,
                &msg_id,
                &plaintext,
            )?;
            let data = serde_json::to_vec(&env)?;
            match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                Ok(_) => return Ok(()),
                Err(libp2p::gossipsub::PublishError::MessageTooLarge) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(anyhow::anyhow!("room payload exceeds gossipsub size limit"))
    }

    /// A copy of the payload with the avatar field cleared — the slim
    /// retry for payloads that exceed the gossipsub transmit limit.
    /// Returns `None` when the variant carries no avatar to strip.
    fn room_payload_slim(payload: &crate::p2p::RoomPayload) -> Option<crate::p2p::RoomPayload> {
        match payload.clone() {
            crate::p2p::RoomPayload::Meta { name, avatar: Some(_) } => {
                Some(crate::p2p::RoomPayload::Meta { name, avatar: None })
            }
            crate::p2p::RoomPayload::MemberJoined { peer_id, name, avatar: Some(_) } => {
                Some(crate::p2p::RoomPayload::MemberJoined { peer_id, name, avatar: None })
            }
            crate::p2p::RoomPayload::MemberProfile { peer_id, name, avatar: Some(_) } => {
                Some(crate::p2p::RoomPayload::MemberProfile { peer_id, name, avatar: None })
            }
            _ => None,
        }
    }

    /// Rotate the in-memory key for a subscribed room. The topic stays
    /// subscribed — room id is stable across key generations.
    pub fn update_room_key(&mut self, room_id: &str, room_key: [u8; 32]) {
        self.room_keys.insert(room_id.to_string(), room_key);
    }

    /// Unsubscribe from a room topic and drop its key material.
    pub fn leave_room(&mut self, room_id: &str) {
        self.room_keys.remove(room_id);
        let topic = libp2p::gossipsub::IdentTopic::new(Self::room_topic(room_id));
        let _ = self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
    }

    /// Gossipsub topic name — derived from the room id, so topic names never
    /// leak room metadata beyond the id itself.
    pub fn room_topic(room_id: &str) -> String {
        format!("noid-room-{}", room_id)
    }
}
