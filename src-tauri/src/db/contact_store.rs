use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// `id` is the contact's peer id — stored field-encrypted, deduplicated
    /// through the deterministic `id_hmac` token.
    /// True when `peer_id` is an accepted contact (S22 — wire-status
    /// filtering for receipts/typing).
    pub async fn is_contact(&self, peer_id: &str) -> Result<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE id_hmac = ?")
            .bind(self.hmac("contact.id", peer_id))
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    pub async fn add_contact(&self, id: &str, nickname: &str, avatar: Option<&str>) -> Result<()> {
        sqlx::query("DELETE FROM contacts WHERE id_hmac = ?")
            .bind(self.hmac("contact.id", id))
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO contacts (id, nickname, avatar, id_hmac) VALUES (?, ?, ?, ?)")
            .bind(self.enc_text(id)?)
            .bind(self.enc_text(nickname)?)
            .bind(match avatar {
                Some(a) => Some(self.enc_text(a)?),
                None => None,
            })
            .bind(self.hmac("contact.id", id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// DB2: write-through to `peer_public_keys` (keyed by peer_hmac,
    /// independent of contact acceptance) plus the legacy contacts column.
    /// The old UPDATE-only path silently no-oped for peers without a
    /// contacts row — the key was lost and every next exchange re-fired.
    pub async fn save_contact_public_key(
        &self,
        peer_id: &str,
        public_key: &[u8],
    ) -> Result<()> {
        let hmac = self.hmac("contact.id", peer_id);
        sqlx::query(
            "INSERT OR REPLACE INTO peer_public_keys (peer_hmac, public_key) VALUES (?, ?)",
        )
        .bind(&hmac)
        .bind(public_key)
        .execute(&self.pool)
        .await?;
        sqlx::query("UPDATE contacts SET public_key = ? WHERE id_hmac = ?")
            .bind(public_key)
            .bind(&hmac)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_contact_public_key(
        &self,
        peer_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let hmac = self.hmac("contact.id", peer_id);
        // peer_public_keys is the canonical store; contacts.public_key is
        // the pre-014 fallback for keys written before the table existed.
        let row = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT public_key FROM peer_public_keys WHERE peer_hmac = ?",
        )
        .bind(&hmac)
        .fetch_optional(&self.pool)
        .await?;
        if let Some((key,)) = row {
            return Ok(Some(key));
        }
        let row = sqlx::query_as::<_, (Option<Vec<u8>>,)>(
            "SELECT public_key FROM contacts WHERE id_hmac = ?",
        )
        .bind(&hmac)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.0))
    }

    pub async fn get_contacts(&self) -> Result<Vec<(String, Option<String>, Option<String>)>> {
        let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
            "SELECT id, nickname, avatar FROM contacts",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(id, nickname, avatar)| {
                Ok((
                    self.dec_text(&id)?,
                    match nickname {
                        Some(n) => Some(self.dec_text(&n)?),
                        None => None,
                    },
                    match avatar {
                        Some(a) => Some(self.dec_text(&a)?),
                        None => None,
                    },
                ))
            }),
            "contact",
        ))
    }

    /// `sender_id` is the requester's peer id — field-encrypted, deduped by
    /// `sender_hmac`. `message`/`nickname` are encrypted as well.
    pub async fn add_contact_request(
        &self,
        sender_id: &str,
        message: &str,
        nickname: &str,
        avatar: Option<&str>,
    ) -> Result<()> {
        sqlx::query("DELETE FROM contact_requests WHERE sender_hmac = ?")
            .bind(self.hmac("contact_request.sender", sender_id))
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO contact_requests (sender_id, message, nickname, avatar, sender_hmac) VALUES (?, ?, ?, ?, ?)")
            .bind(self.enc_text(sender_id)?)
            .bind(self.enc_text(message)?)
            .bind(self.enc_text(nickname)?)
            .bind(match avatar {
                Some(a) => Some(self.enc_text(a)?),
                None => None,
            })
            .bind(self.hmac("contact_request.sender", sender_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_contact_requests(
        &self,
    ) -> Result<Vec<(String, String, String, Option<String>)>> {
        let rows = sqlx::query_as::<_, (String, String, String, Option<String>)>(
            "SELECT sender_id, message, nickname, avatar FROM contact_requests",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(sender, message, nickname, avatar)| {
                Ok((
                    self.dec_text(&sender)?,
                    self.dec_text(&message)?,
                    self.dec_text(&nickname)?,
                    match avatar {
                        Some(a) => Some(self.dec_text(&a)?),
                        None => None,
                    },
                ))
            }),
            "contact_request",
        ))
    }

    pub async fn delete_contact_request(&self, sender_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM contact_requests WHERE sender_hmac = ?")
            .bind(self.hmac("contact_request.sender", sender_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// S16: record that WE sent a contact request to `peer_id` — an inbound
    /// `ContactAccept` is only legit as a reply to one of these.
    pub async fn add_outgoing_contact_request(&self, peer_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO outgoing_contact_requests (peer_id, peer_hmac) VALUES (?, ?)",
        )
        .bind(self.enc_text(peer_id)?)
        .bind(self.hmac("contact_request.outgoing", peer_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// True when an outgoing request to `peer_id` is on file.
    pub async fn has_outgoing_contact_request(&self, peer_id: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(*) FROM outgoing_contact_requests WHERE peer_hmac = ?",
        )
        .bind(self.hmac("contact_request.outgoing", peer_id))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(n,)| n > 0).unwrap_or(false))
    }

    /// Consume the outgoing-request marker (accept processed or request withdrawn).
    pub async fn delete_outgoing_contact_request(&self, peer_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM outgoing_contact_requests WHERE peer_hmac = ?")
            .bind(self.hmac("contact_request.outgoing", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes the contact row together with every other record bound to this
    /// peer: contact requests, direct-message history, pending outbox and the
    /// ratchet session (a re-added contact must not inherit a stale session —
    /// it would fail to decrypt anyway and could poison recovery).
    ///
    /// Every lookup goes through the deterministic `*_hmac` columns — the
    /// plaintext columns hold randomized ciphertext and can never be matched
    /// by `WHERE id = ?`.
    pub async fn delete_contact(&self, peer_id: &str) -> Result<()> {
        // DB8: all deletes in one transaction — a partial delete used to
        // leave orphaned history/pending/session rows on mid-failure.
        // DB9: room_members rows for this peer are removed too — a deleted
        // contact must not keep receiving rekey material.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM contacts WHERE id_hmac = ?")
            .bind(self.hmac("contact.id", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM contact_requests WHERE sender_hmac = ?")
            .bind(self.hmac("contact_request.sender", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM outgoing_contact_requests WHERE peer_hmac = ?")
            .bind(self.hmac("contact_request.outgoing", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM messages WHERE sender_hmac = ? OR receiver_hmac = ?",
        )
        .bind(self.hmac("msg.sender", peer_id))
        .bind(self.hmac("msg.receiver", peer_id))
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM pending_messages WHERE peer_hmac = ?")
            .bind(self.hmac("pending.peer", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM ratchet_states WHERE peer_hmac = ?")
            .bind(self.hmac("ratchet.peer", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM peer_public_keys WHERE peer_hmac = ?")
            .bind(self.hmac("contact.id", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM room_members WHERE peer_hmac = ?")
            .bind(self.hmac("room.member", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_room_invites WHERE inviter_hmac = ?")
            .bind(self.hmac("room_invite.inviter", peer_id))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
