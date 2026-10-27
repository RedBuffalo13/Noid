-- Add username and publication status to profile

ALTER TABLE profile ADD COLUMN username TEXT;
ALTER TABLE profile ADD COLUMN username_published BOOLEAN DEFAULT 0;
