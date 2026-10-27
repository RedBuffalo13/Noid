use anyhow::Result;
use crate::db::database::Database;

/// Full room record for the settings UI — all fields decrypted.
pub struct RoomInfo {
    pub id: String,
    pub name: String,
    pub avatar: Option<String>,
    pub owner: Option<String>,
    pub key_epoch: u32,
}

/// A room member row, decrypted — identity + approval + announced profile.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomMember {
    pub peer_id: String,
    pub approved: bool,
    pub name: Option<String>,
    pub avatar: Option<String>,
}

impl Database {
    /// Create a room record with its key material (field-encrypted at rest).
    /// `name_hmac` is written alongside — without it the plaintext-field
    /// migration would treat the encrypted name as legacy plaintext and
    /// double-encrypt it on the next login.
    pub async fn create_room(&self, id: &str, name: &str) -> Result<()> {
        sqlx::query("INSERT INTO rooms (id, name, name_hmac) VALUES (?, ?, ?)")
            .bind(id)
            .bind(self.enc_text(name)?)
            .bind(self.hmac("room.name", name))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Create a room together with its AES-256 key (encrypted at rest).
    pub async fn create_room_with_key(&self, id: &str, name: &str, key: &[u8; 32]) -> Result<()> {
        sqlx::query("INSERT INTO rooms (id, name, name_hmac, key_material) VALUES (?, ?, ?, ?)")
            .bind(id)
            .bind(self.enc_text(name)?)
            .bind(self.hmac("room.name", name))
            .bind(self.enc_bytes(key)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Create a room with key + owner + avatar (all field-encrypted) at a
    /// given key epoch — 0 for self-created rooms, the invite's epoch for
    /// invited ones.
    pub async fn create_room_full(
        &self,
        id: &str,
        name: &str,
        key: &[u8; 32],
        owner: Option<&str>,
        avatar: Option<&str>,
        key_epoch: u32,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO rooms (id, name, name_hmac, key_material, owner_peer_id, owner_hmac, avatar, key_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(self.enc_text(name)?)
        .bind(self.hmac("room.name", name))
        .bind(self.enc_bytes(key)?)
        .bind(match owner {
            Some(o) => Some(self.enc_text(o)?),
            None => None,
        })
        .bind(owner.map(|o| self.hmac("room.owner", o)))
        .bind(match avatar {
            Some(a) => Some(self.enc_text(a)?),
            None => None,
        })
        .bind(key_epoch as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Decrypted room record for the settings UI.
    pub async fn get_room_info(&self, room_id: &str) -> Result<Option<RoomInfo>> {
        type Row = (String, String, Option<String>, Option<String>, i64);
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, name, avatar, owner_peer_id, key_epoch FROM rooms WHERE id = ?",
        )
        .bind(room_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((id, name, avatar, owner, epoch)) => {
                // DB21/DB4: an undecryptable owner or name must not fail the
                // whole read — owner degrades to None (= unset → Meta
                // convergence can repair it), name to a placeholder.
                let owner = match owner {
                    Some(o) => match self.dec_text(&o) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            log::warn!("room {}: owner undecryptable, treating as unset: {}", id, e);
                            None
                        }
                    },
                    None => None,
                };
                let name = self.dec_text(&name).unwrap_or_else(|e| {
                    log::warn!("room {}: name decrypt failed: {}", id, e);
                    format!("Room {}", id.chars().take(8).collect::<String>())
                });
                Ok(Some(RoomInfo {
                    id,
                    name,
                    avatar: match avatar {
                        Some(a) => self.dec_text(&a).ok(),
                        None => None,
                    },
                    owner,
                    key_epoch: epoch as u32,
                }))
            }
            None => Ok(None),
        }
    }

    /// Owner-only rename (caller enforces authorization).
    pub async fn rename_room(&self, room_id: &str, name: &str) -> Result<()> {
        sqlx::query("UPDATE rooms SET name = ?, name_hmac = ? WHERE id = ?")
            .bind(self.enc_text(name)?)
            .bind(self.hmac("room.name", name))
            .bind(room_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Owner-only avatar update (data-URL, size-validated by the caller).
    pub async fn set_room_avatar(&self, room_id: &str, avatar: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE rooms SET avatar = ? WHERE id = ?")
            .bind(match avatar {
                Some(a) => Some(self.enc_text(a)?),
                None => None,
            })
            .bind(room_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a member row by peer identity.
    pub async fn remove_room_member(&self, room_id: &str, peer_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM room_members WHERE room_id = ? AND peer_hmac = ?")
            .bind(room_id)
            .bind(self.hmac("room.member", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// True when `peer_id` is an APPROVED member of the room (S8: a pending
    /// invitee row — `is_approved = 0` — must not satisfy key-distribution
    /// checks like KeySyncRequest or reconnect resend).
    pub async fn is_room_member(&self, room_id: &str, peer_id: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(*) FROM room_members WHERE room_id = ? AND peer_hmac = ? AND is_approved = 1",
        )
        .bind(room_id)
        .bind(self.hmac("room.member", peer_id))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(n,)| n > 0).unwrap_or(false))
    }

    /// Rotate the stored room key and bump the epoch in one write — the
    /// epoch guards against stale KeyUpdates arriving out of order.
    pub async fn update_room_key(
        &self,
        room_id: &str,
        key: &[u8; 32],
        epoch: u32,
    ) -> Result<()> {
        sqlx::query("UPDATE rooms SET key_material = ?, key_epoch = ? WHERE id = ?")
            .bind(self.enc_bytes(key)?)
            .bind(epoch as i64)
            .bind(room_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Rooms owned by `peer_id` — used to fan out KeyUpdates on reconnect.
    pub async fn rooms_owned_by(&self, peer_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT id FROM rooms WHERE owner_hmac = ?",
        )
        .bind(self.hmac("room.owner", peer_id))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Delete a room and everything attached to it (members, history,
    /// pending invites). DB8: single transaction; DB9: `pending_room_invites`
    /// used to survive — accepting one after delete re-materialized the room.
    pub async fn delete_room(&self, room_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM room_members WHERE room_id = ?")
            .bind(room_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM room_messages WHERE room_id = ?")
            .bind(room_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_room_invites WHERE room_id = ?")
            .bind(room_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM rooms WHERE id = ?")
            .bind(room_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Decrypt a room's key material. None if the room is unknown or has no key.
    pub async fn get_room_key(&self, room_id: &str) -> Result<Option<[u8; 32]>> {
        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT key_material FROM rooms WHERE id = ?")
                .bind(room_id)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((Some(k),)) => {
                let raw = self.dec_bytes(&k)?;
                let key: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("room key wrong length"))?;
                Ok(Some(key))
            }
            _ => Ok(None),
        }
    }

    /// List rooms as (id, name) — name decrypted. A single corrupt row
    /// degrades to a placeholder instead of hiding every room.
    pub async fn list_rooms(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query_as::<_, (String, String)>("SELECT id, name FROM rooms")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name)| {
                let name = self.dec_text(&name).unwrap_or_else(|e| {
                    log::warn!("room {}: name decrypt failed: {}", id, e);
                    format!("Room {}", id.chars().take(8).collect::<String>())
                });
                (id, name)
            })
            .collect())
    }

    /// `peer_id` is field-encrypted; `peer_hmac` is the lookup token.
    /// Ciphertext is non-deterministic, so we delete-then-insert on the HMAC
    /// to keep membership a logical upsert. Profile columns survive the
    /// rewrite only when freshly supplied — callers that re-add a member
    /// should re-set the profile afterwards (delete-then-insert clears it).
    pub async fn add_room_member(
        &self,
        room_id: &str,
        peer_id: &str,
        approved: bool,
    ) -> Result<()> {
        let hmac = self.hmac("room.member", peer_id);
        sqlx::query("DELETE FROM room_members WHERE room_id = ? AND peer_hmac = ?")
            .bind(room_id)
            .bind(&hmac)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO room_members (room_id, peer_id, is_approved, peer_hmac) VALUES (?, ?, ?, ?)")
            .bind(room_id)
            .bind(self.enc_text(peer_id)?)
            .bind(approved)
            .bind(&hmac)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store a member's announced profile (display name + avatar,
    /// field-encrypted). No-op when the peer is not a member — profiles
    /// only attach to existing membership rows.
    pub async fn set_member_profile(
        &self,
        room_id: &str,
        peer_id: &str,
        name: Option<&str>,
        avatar: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE room_members SET display_name = ?, avatar = ? WHERE room_id = ? AND peer_hmac = ?",
        )
        .bind(match name {
            Some(n) => Some(self.enc_text(n)?),
            None => None,
        })
        .bind(match avatar {
            Some(a) => Some(self.enc_text(a)?),
            None => None,
        })
        .bind(room_id)
        .bind(self.hmac("room.member", peer_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Decrypted member list for a room with announced profiles.
    pub async fn get_room_members(&self, room_id: &str) -> Result<Vec<RoomMember>> {
        let rows = sqlx::query_as::<_, (String, bool, Option<String>, Option<String>)>(
            "SELECT peer_id, is_approved, display_name, avatar FROM room_members WHERE room_id = ?",
        )
        .bind(room_id)
        .fetch_all(&self.pool)
        .await?;
        // DB4: one corrupt member row must not hide the roster.
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(p, a, n, av)| {
                Ok(RoomMember {
                    peer_id: self.dec_text(&p)?,
                    approved: a,
                    name: self.dec_opt(n)?,
                    avatar: self.dec_opt(av)?,
                })
            }),
            "room_member",
        ))
    }

    /// Unconditional owner write — used by the legacy-owner backfill where
    /// caller already validated that the room is ownerless locally.
    pub async fn set_room_owner(&self, room_id: &str, owner: &str) -> Result<()> {
        sqlx::query("UPDATE rooms SET owner_peer_id = ?, owner_hmac = ? WHERE id = ?")
            .bind(self.enc_text(owner)?)
            .bind(self.hmac("room.owner", owner))
            .bind(room_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically set the owner of a room that has no recorded owner —
    /// the UPDATE only lands while `owner_peer_id` is still NULL or still
    /// holds `current_owner` (a stale/garbage value such as a pre-P2P
    /// placeholder). Returns true when the write won. Used by the
    /// `Meta{owner}` convergence path — never user-triggered.
    pub async fn set_room_owner_if_unset(
        &self,
        room_id: &str,
        current_owner: Option<&str>,
        new_owner: &str,
    ) -> Result<bool> {
        // DB21: legacy rows carry a PLAINTEXT owner with NULL owner_hmac —
        // `owner_hmac = hmac(current)` never matches them, so Meta
        // convergence silently failed. Match the raw plaintext too.
        let res = sqlx::query(
            "UPDATE rooms SET owner_peer_id = ?, owner_hmac = ? WHERE id = ? AND \
             (owner_peer_id IS NULL OR owner_hmac = ? OR (owner_hmac IS NULL AND owner_peer_id = ?))",
        )
        .bind(self.enc_text(new_owner)?)
        .bind(self.hmac("room.owner", new_owner))
        .bind(room_id)
        .bind(self.hmac("room.owner", current_owner.unwrap_or("")))
        .bind(current_owner.unwrap_or(""))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Legacy rooms created before owner tracking carry a NULL or
    /// non-PeerId owner. Deterministic backfill: invitees always land in
    /// `room_members`, so a room where WE are absent was created locally —
    /// self-assign ownership. Rooms where we ARE a member stay unset and
    /// converge later via the creator's `Meta{owner}` control message.
    /// Returns the ids we self-assigned (caller broadcasts `Meta{owner}`).
    pub async fn backfill_room_owners(&self, my_id: &str) -> Result<Vec<String>> {
        let rooms = self.list_rooms().await?;
        let mut assigned = Vec::new();
        for (room_id, _) in rooms {
            // DB21: one broken room must not abort the whole backfill.
            let info = match self.get_room_info(&room_id).await {
                Ok(Some(info)) => info,
                Ok(None) => continue,
                Err(e) => {
                    log::warn!("backfill_room_owners: skipping {}: {}", room_id, e);
                    continue;
                }
            };
            let owner_valid = info
                .owner
                .as_deref()
                .map(|o| crate::validation::parse_peer_id(o).is_ok())
                .unwrap_or(false);
            if owner_valid {
                continue;
            }
            let members = self.get_room_members(&room_id).await.unwrap_or_default();
            if members.iter().any(|m| m.peer_id == my_id) {
                continue;
            }
            if let Err(e) = self.set_room_owner(&room_id, my_id).await {
                log::warn!("backfill_room_owners: set owner failed for {}: {}", room_id, e);
                continue;
            }
            log::info!("Room {}: owner backfilled to self (locally created)", room_id);
            assigned.push(room_id);
        }
        Ok(assigned)
    }

    pub async fn approve_member(&self, room_id: &str, peer_id: &str) -> Result<()> {
        sqlx::query("UPDATE room_members SET is_approved = 1 WHERE room_id = ? AND peer_hmac = ?")
            .bind(room_id)
            .bind(self.hmac("room.member", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store a room message — sender and content field-encrypted.
    /// Returns false when the message id was already stored (dedup).
    pub async fn add_room_message(
        &self,
        msg_id: &str,
        room_id: &str,
        sender_peer_id: &str,
        content: &[u8],
        timestamp: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO room_messages (id, room_id, sender_peer_id, sender_hmac, content, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(msg_id)
        .bind(room_id)
        .bind(self.enc_text(sender_peer_id)?)
        .bind(self.hmac("room.sender", sender_peer_id))
        .bind(self.enc_bytes(content)?)
        .bind(Self::sanitize_ts(timestamp))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Room history: (id, sender_peer_id, content, timestamp) — decrypted.
    pub async fn get_room_messages(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, String)>> {
        // DB12: bound room history the same way as direct history.
        let mut rows = sqlx::query_as::<_, (String, String, Vec<u8>, String)>(
            "SELECT id, sender_peer_id, content, timestamp FROM room_messages WHERE room_id = ? ORDER BY timestamp DESC LIMIT 500",
        )
        .bind(room_id)
        .fetch_all(&self.pool)
        .await?;
        rows.reverse();
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(id, sender, content, ts)| {
                Ok((
                    id,
                    self.dec_text(&sender)?,
                    String::from_utf8(self.dec_bytes(&content)?)
                        .unwrap_or_else(|_| "[undecryptable]".into()),
                    ts,
                ))
            }),
            "room_message",
        ))
    }
}
