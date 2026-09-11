-- M1: institution callbacks are verified with the governed signing-key
-- registry (institution_signing_keys), so revoking or expiring a key stops
-- callbacks signed with it. The key used is recorded with each receipt so
-- buffered callbacks can be re-checked before they are applied.
ALTER TABLE rwa.callback_receipts
  ADD COLUMN IF NOT EXISTS signing_key_id text
    CHECK (signing_key_id IS NULL OR signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');
