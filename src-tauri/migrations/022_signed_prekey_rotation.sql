-- SEC-1111-07: signed-prekey rotation bookkeeping. The previous SPK stays
-- as key_type='signed_prekey_prev' so inits signed by a still-propagating
-- bundle keep working during the overlap window.
-- `prekeys.created_at` already exists since migration 008 — this step only
-- adds the index the rotation lookup uses.
CREATE INDEX IF NOT EXISTS idx_prekeys_created ON prekeys(created_at);
