-- Phase 6 remediation: missing indexes + dead-capacity cleanup.

-- DB15: pending_messages.message_id — every wire ack (MessageDelivered /
-- MailboxStoreAck) hits `delete_pending_message_by_id` /
-- `pending_exists_by_message_id`, both keyed on (peer_hmac, message_id).
-- Without this index each wire event was a full table scan.
CREATE INDEX IF NOT EXISTS idx_pending_message_id
    ON pending_messages(message_id);

-- DB20: prekeys — consumed OTPKs accumulate forever; the pool lookup
-- filters (key_type, is_consumed) but had no index.
CREATE INDEX IF NOT EXISTS idx_prekeys_type_consumed
    ON prekeys(key_type, is_consumed);

-- DB20: mailbox expiry cleanup runs hourly on expires_at — index it.
CREATE INDEX IF NOT EXISTS idx_mailbox_expires
    ON mailbox_storage(expires_at);

-- DB20: consumed one-time prekeys are dead weight — purge what has
-- already been consumed (the keys can never be re-served).
DELETE FROM prekeys WHERE key_type = 'one_time_prekey' AND is_consumed = 1;
