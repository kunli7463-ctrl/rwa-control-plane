ALTER TABLE rwa.outbox_events
  DROP CONSTRAINT IF EXISTS outbox_events_status_check;

ALTER TABLE rwa.outbox_events
  ADD CONSTRAINT outbox_events_status_check
  CHECK (status IN ('PENDING', 'CLAIMED', 'PUBLISHED', 'FAILED', 'DEAD'));

ALTER TABLE rwa.outbox_events
  ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz;

DROP INDEX IF EXISTS rwa.outbox_dispatch_idx;
CREATE INDEX outbox_dispatch_idx
  ON rwa.outbox_events(status, available_at, lease_expires_at, created_at)
  WHERE status IN ('PENDING', 'FAILED', 'CLAIMED');

CREATE TABLE IF NOT EXISTS rwa.inbox_consumptions (
  consumer_name text NOT NULL,
  event_id text NOT NULL REFERENCES rwa.outbox_events(id),
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (consumer_name, event_id)
);

CREATE TABLE IF NOT EXISTS rwa.register_callback_events (
  event_id text PRIMARY KEY REFERENCES rwa.outbox_events(id),
  transaction_id text NOT NULL,
  callback_type text NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS inbox_consumptions_append_only_guard ON rwa.inbox_consumptions;
CREATE TRIGGER inbox_consumptions_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.inbox_consumptions
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

DROP TRIGGER IF EXISTS register_callback_events_append_only_guard ON rwa.register_callback_events;
CREATE TRIGGER register_callback_events_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.register_callback_events
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();
