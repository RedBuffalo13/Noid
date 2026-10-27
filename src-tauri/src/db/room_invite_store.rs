use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Store a received room invite awaiting user consent. Keyed by
    /// `room_id` — a re-offer replaces the stale row.
    pub async fn add_pending_room_invite(
        &self,
        room_id: &str,
        inviter: &str,
        name: Option<&str>,
        avatar: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO pending_room_invites \
             (room_id, inviter_peer_id, inviter_hmac, name, avatar) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(room_id)
        .bind(self.enc_text(inviter)?)
        .bind(self.hmac("room_invite.inviter", inviter))
        .bind(match name {
            Some(n) => Some(self.enc_text(n)?),
            None => None,
        })
        .bind(match avatar {
            Some(a) => Some(self.enc_text(a)?),
            None => None,
        })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All pending invites: (room_id, inviter_peer_id, name, avatar).
    pub async fn get_pending_room_invites(
        &self,
    ) -> Result<Vec<(String, String, Option<String>, Option<String>)>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
            "SELECT room_id, inviter_peer_id, name, avatar FROM pending_room_invites \
             ORDER BY received_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(room_id, inviter, name, avatar)| {
                Ok((
                    room_id,
                    self.dec_text(&inviter)?,
                    match name {
                        Some(n) => Some(self.dec_text(&n)?),
                        None => None,
                    },
                    match avatar {
                        Some(a) => Some(self.dec_text(&a)?),
                        None => None,
                    },
                ))
            }),
            "room_invite",
        ))
    }

    /// The inviter peer id for one pending invite — the accept/decline
    /// commands look it up so the frontend never supplies the peer.
    pub async fn get_pending_room_invite_inviter(&self, room_id: &str) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT inviter_peer_id FROM pending_room_invites WHERE room_id = ?",
        )
        .bind(room_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((inviter,)) => Ok(Some(self.dec_text(&inviter)?)),
            None => Ok(None),
        }
    }

    pub async fn delete_pending_room_invite(&self, room_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM pending_room_invites WHERE room_id = ?")
            .bind(room_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
