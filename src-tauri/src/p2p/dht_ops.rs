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
        let _ = self.swarm.behaviour_mut().gossipsub.subscribe(&topic);
        self.subscribe_rotating(room_id);
        Ok(())
    }

    /// META-04: (re)build rotating-topic subscriptions for `room_id` —
    /// today + yesterday so a straddling member keeps receiving at the
    /// rotation boundary. Cheap to call repeatedly: re-subscribing an
    /// existing topic is a no-op.
    pub(crate) fn subscribe_rotating(&mut self, room_id: &str) {
        let Some(key) = self.room_keys.get(room_id).copied() else {
            return;
        };
        let day = crate::p2p::blind_box::current_day();
        for d in [day, day.saturating_sub(1)] {
            let t = crate::security::room_crypto::rotating_topic(&key, d);
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&libp2p::gossipsub::IdentTopic::new(&t));
            self.room_topics.insert(t, room_id.to_string());
        }
        self.room_topics_day = day;
    }

    /// META-04: called on a periodic tick — when the day rolls over,
    /// rebuild rotating subscriptions for every joined room and drop the
    /// stale day-1 mapping.
    pub fn refresh_rotating_topics(&mut self) {
        if self.room_topics_day == crate::p2p::blind_box::current_day() {
            return;
        }
        self.room_topics
            .retain(|_, rid| self.room_keys.contains_key(rid));
        for room_id in self.room_keys.keys().cloned().collect::<Vec<_>>() {
            self.subscribe_rotating(&room_id);
        }
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
        let key = *self
            .room_keys
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("not a member of room {}", room_id))?;
        let plaintext = serde_json::to_vec(&crate::p2p::RoomPayload::Chat {
            content: content.to_string(),
        })?;
        let msg_id = uuid::Uuid::new_v4().to_string();
        self.publish_v2(room_id, &msg_id, &plaintext);
        let env = crate::security::room_crypto::seal(
            &key,
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

    /// META-04: publish the same payload as a `NRV2` sealed blob to
    /// today's rotating topic. Same `msg_id` as the V1 envelope →
    /// members subscribed to both dedup. Best-effort only.
    fn publish_v2(&mut self, room_id: &str, msg_id: &str, plaintext: &[u8]) {
        let Some(key) = self.room_keys.get(room_id).copied() else {
            return;
        };
        self.subscribe_rotating(room_id);
        let Ok(blob) = crate::security::room_crypto::seal_v2(
            &key,
            room_id,
            &self.identity_keypair,
            msg_id,
            plaintext,
        ) else {
            return;
        };
        let topic = libp2p::gossipsub::IdentTopic::new(
            crate::security::room_crypto::rotating_topic(
                &key,
                crate::p2p::blind_box::current_day(),
            ),
        );
        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, blob);
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
        let key = *self
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
            self.publish_v2(room_id, &msg_id, &plaintext);
            let env = crate::security::room_crypto::seal(
                &key,
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
        if let Some(mut k) = self.room_keys.remove(room_id) {
            use zeroize::Zeroize;
            k.zeroize();
        }
        let topic = libp2p::gossipsub::IdentTopic::new(Self::room_topic(room_id));
        let _ = self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
        // META-04: rotating subscriptions die with the key.
        self.room_topics.retain(|t, rid| {
            if rid == room_id {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .unsubscribe(&libp2p::gossipsub::IdentTopic::new(t));
                false
            } else {
                true
            }
        });
    }

    /// Gossipsub topic name — derived from the room id, so topic names never
    /// leak room metadata beyond the id itself.
    pub fn room_topic(room_id: &str) -> String {
        format!("noid-room-{}", room_id)
    }
}
