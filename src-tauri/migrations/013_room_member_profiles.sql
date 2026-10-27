-- Room member profiles: display name + avatar, field-encrypted at rest.
-- New columns are only ever written encrypted, so no hmac marker columns
-- are needed (no equality lookup on them either).
ALTER TABLE room_members ADD COLUMN display_name TEXT;
ALTER TABLE room_members ADD COLUMN avatar TEXT;
