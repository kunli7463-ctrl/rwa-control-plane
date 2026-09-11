-- M4: transactions remember the institution that originated them so broker
-- disclosure and confidential-transfer operations are scoped to that
-- institution instead of every broker in the tenant.
ALTER TABLE rwa.transaction_intents
  ADD COLUMN IF NOT EXISTS originating_institution_id text REFERENCES rwa.institutions(id);

CREATE INDEX IF NOT EXISTS transaction_intents_originating_institution_idx
  ON rwa.transaction_intents(tenant_id,product_id,originating_institution_id);

CREATE OR REPLACE FUNCTION rwa.guard_transaction_originating_institution() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.originating_institution_id IS DISTINCT FROM OLD.originating_institution_id THEN
    RAISE EXCEPTION 'transaction originating institution is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS transaction_originating_institution_guard ON rwa.transaction_intents;
CREATE TRIGGER transaction_originating_institution_guard
BEFORE UPDATE OF originating_institution_id ON rwa.transaction_intents
FOR EACH ROW EXECUTE FUNCTION rwa.guard_transaction_originating_institution();
