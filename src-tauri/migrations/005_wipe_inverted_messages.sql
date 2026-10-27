-- Migration 005: Wipe messages with inverted sender/receiver
-- Due to bug in send_chat_message.rs:43 (fixed), outgoing messages were stored
-- with sender_id=peer_id, receiver_id=my_id (inverted). Since we cannot reliably
-- distinguish inverted outgoing from legitimate incoming, we wipe all messages
-- and pending_messages to start clean with correct attribution.
DELETE FROM messages;
DELETE FROM pending_messages;
