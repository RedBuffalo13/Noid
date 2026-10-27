-- Field-encryption support: deterministic HMAC lookup columns.
-- Sensitive values are stored AES-256-GCM encrypted in the original columns;
-- these hmac columns hold HMAC-SHA256(master_key, ns || value) tokens so
-- equality lookups keep working without plaintext.

ALTER TABLE messages ADD COLUMN sender_hmac TEXT;
ALTER TABLE messages ADD COLUMN receiver_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_messages_sender_hmac ON messages(sender_hmac);
CREATE INDEX IF NOT EXISTS idx_messages_receiver_hmac ON messages(receiver_hmac);

ALTER TABLE pending_messages ADD COLUMN peer_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_pending_peer_hmac ON pending_messages(peer_hmac);

ALTER TABLE mailbox_storage ADD COLUMN recipient_hmac TEXT;
ALTER TABLE mailbox_storage ADD COLUMN sender_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient_hmac ON mailbox_storage(recipient_hmac);
CREATE INDEX IF NOT EXISTS idx_mailbox_sender_hmac ON mailbox_storage(sender_hmac);

ALTER TABLE ratchet_states ADD COLUMN peer_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_ratchet_peer_hmac ON ratchet_states(peer_hmac);

ALTER TABLE contacts ADD COLUMN id_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_contacts_id_hmac ON contacts(id_hmac);

ALTER TABLE contact_requests ADD COLUMN sender_hmac TEXT;
CREATE INDEX IF NOT EXISTS idx_contact_requests_sender_hmac ON contact_requests(sender_hmac);

ALTER TABLE shared_folders ADD COLUMN path_hmac TEXT;

ALTER TABLE room_members ADD COLUMN peer_hmac TEXT;
