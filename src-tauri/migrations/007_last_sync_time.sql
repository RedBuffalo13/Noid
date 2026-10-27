-- Phase 4.4: Move last_sync_time from profile.avatar to a dedicated column
ALTER TABLE profile ADD COLUMN last_sync_time TEXT;
