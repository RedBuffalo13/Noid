-- Add message_id column to pending_messages for precise deletion

ALTER TABLE pending_messages ADD COLUMN message_id TEXT;
