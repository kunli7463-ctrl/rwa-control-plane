ALTER TABLE rwa.outbox_events
  ADD COLUMN IF NOT EXISTS replay_count integer NOT NULL DEFAULT 0 CHECK (replay_count >= 0);

CREATE TABLE IF NOT EXISTS rwa.dead_letter_replay_requests (
  id text PRIMARY KEY,
  event_id text NOT NULL REFERENCES rwa.outbox_events(id),
  tenant_id text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'EXECUTED', 'REJECTED')),
  maker_ref text NOT NULL,
  reason text NOT NULL CHECK (length(reason) >= 8),
  dead_error_snapshot text,
  checker_ref text,
  checker_decision text CHECK (checker_decision IN ('APPROVE', 'REJECT')),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  decided_at timestamptz,
  executed_at timestamptz,
  CHECK (checker_ref IS NULL OR checker_ref <> maker_ref),
  CHECK ((status='PENDING' AND checker_ref IS NULL AND checker_decision IS NULL AND decided_at IS NULL AND executed_at IS NULL)
      OR (status='REJECTED' AND checker_ref IS NOT NULL AND checker_decision='REJECT' AND decided_at IS NOT NULL AND executed_at IS NULL)
      OR (status='EXECUTED' AND checker_ref IS NOT NULL AND checker_decision='APPROVE' AND decided_at IS NOT NULL AND executed_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS dead_letter_one_pending_request
  ON rwa.dead_letter_replay_requests(event_id)
  WHERE status='PENDING';

CREATE OR REPLACE FUNCTION rwa.validate_dead_letter_replay_request() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  event_status text;
  event_tenant text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT status,tenant_id INTO event_status,event_tenant
    FROM rwa.outbox_events WHERE id=NEW.event_id FOR UPDATE;
    IF event_status IS DISTINCT FROM 'DEAD' OR event_tenant IS DISTINCT FROM NEW.tenant_id THEN
      RAISE EXCEPTION 'replay request requires a DEAD event in the same tenant' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status <> 'PENDING' OR NEW.status NOT IN ('EXECUTED','REJECTED') THEN
    RAISE EXCEPTION 'invalid dead-letter replay transition' USING ERRCODE='55000';
  END IF;
  IF NEW.event_id IS DISTINCT FROM OLD.event_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.maker_ref IS DISTINCT FROM OLD.maker_ref OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.dead_error_snapshot IS DISTINCT FROM OLD.dead_error_snapshot OR NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN
    RAISE EXCEPTION 'dead-letter replay request identity is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dead_letter_replay_guard ON rwa.dead_letter_replay_requests;
CREATE TRIGGER dead_letter_replay_guard
BEFORE INSERT OR UPDATE ON rwa.dead_letter_replay_requests
FOR EACH ROW EXECUTE FUNCTION rwa.validate_dead_letter_replay_request();
