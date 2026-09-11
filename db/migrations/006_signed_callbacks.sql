CREATE TABLE IF NOT EXISTS rwa.callback_stream_positions (
  tenant_id text NOT NULL,
  institution_id text NOT NULL REFERENCES rwa.institutions(id),
  product_id text NOT NULL REFERENCES rwa.products(id),
  channel text NOT NULL CHECK (channel IN ('REGISTER', 'CASH', 'CUSTODY')),
  next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,institution_id,product_id,channel)
);

CREATE TABLE IF NOT EXISTS rwa.callback_receipts (
  callback_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  institution_id text NOT NULL REFERENCES rwa.institutions(id),
  product_id text NOT NULL REFERENCES rwa.products(id),
  channel text NOT NULL CHECK (channel IN ('REGISTER', 'CASH', 'CUSTODY')),
  stream_sequence bigint NOT NULL CHECK (stream_sequence > 0),
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id,institution_id,product_id,channel,stream_sequence),
  CHECK (expires_at > occurred_at)
);

CREATE TABLE IF NOT EXISTS rwa.callback_applications (
  callback_id text PRIMARY KEY REFERENCES rwa.callback_receipts(callback_id),
  status text NOT NULL CHECK (status IN ('BUFFERED', 'APPLIED')),
  outcome text CHECK (outcome IN ('CONFIRMED', 'REJECTED', 'PERMANENT_FAILURE')),
  applied_at timestamptz,
  CHECK ((status='BUFFERED' AND outcome IS NULL AND applied_at IS NULL)
      OR (status='APPLIED' AND outcome IS NOT NULL AND applied_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS rwa.callback_effects (
  callback_id text PRIMARY KEY REFERENCES rwa.callback_receipts(callback_id),
  subject_ref text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('CONFIRMED', 'REJECTED', 'PERMANENT_FAILURE')),
  details jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS callback_receipts_append_only_guard ON rwa.callback_receipts;
CREATE TRIGGER callback_receipts_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.callback_receipts
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

DROP TRIGGER IF EXISTS callback_effects_append_only_guard ON rwa.callback_effects;
CREATE TRIGGER callback_effects_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.callback_effects
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION rwa.validate_callback_application_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status <> 'BUFFERED' OR NEW.status <> 'APPLIED'
     OR NEW.callback_id IS DISTINCT FROM OLD.callback_id THEN
    RAISE EXCEPTION 'invalid callback application transition' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS callback_application_guard ON rwa.callback_applications;
CREATE TRIGGER callback_application_guard
BEFORE UPDATE OR DELETE ON rwa.callback_applications
FOR EACH ROW EXECUTE FUNCTION rwa.validate_callback_application_update();
