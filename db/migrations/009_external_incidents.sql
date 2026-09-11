CREATE TABLE IF NOT EXISTS rwa.external_reconciliation_incidents (
  id text PRIMARY KEY,
  callback_id text NOT NULL UNIQUE REFERENCES rwa.callback_receipts(callback_id),
  transaction_id text REFERENCES rwa.transaction_intents(id),
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  channel text NOT NULL CHECK (channel IN ('REGISTER','CASH','CUSTODY')),
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','PENDING_APPROVAL','RESOLVED_ACKNOWLEDGED','RESOLVED_REMEDIATED')),
  severity text NOT NULL CHECK (severity IN ('HIGH','CRITICAL')),
  reason_code text NOT NULL,
  approval_round integer NOT NULL DEFAULT 0 CHECK (approval_round >= 0),
  remediation_reference text,
  row_version bigint NOT NULL DEFAULT 0,
  opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS rwa.external_incident_approvals (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  incident_id text NOT NULL REFERENCES rwa.external_reconciliation_incidents(id),
  approval_round integer NOT NULL CHECK (approval_round > 0),
  role text NOT NULL CHECK (role IN ('MAKER','CHECKER')),
  actor_ref text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ACKNOWLEDGE','REMEDIATE','APPROVE','REJECT')),
  remediation_reference text,
  signature text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (incident_id,approval_round,role),
  CHECK ((role='MAKER' AND decision IN ('ACKNOWLEDGE','REMEDIATE'))
      OR (role='CHECKER' AND decision IN ('APPROVE','REJECT'))),
  CHECK ((role='MAKER' AND decision='REMEDIATE' AND remediation_reference IS NOT NULL)
      OR NOT (role='MAKER' AND decision='REMEDIATE'))
);

CREATE OR REPLACE FUNCTION rwa.enforce_external_incident_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE maker_ref text;
BEGIN
  IF NEW.role <> 'CHECKER' THEN RETURN NEW; END IF;
  SELECT actor_ref INTO maker_ref FROM rwa.external_incident_approvals
   WHERE incident_id=NEW.incident_id AND approval_round=NEW.approval_round AND role='MAKER';
  IF maker_ref IS NULL THEN
    RAISE EXCEPTION 'checker requires maker proposal in the same round' USING ERRCODE='23514';
  END IF;
  IF maker_ref=NEW.actor_ref THEN
    RAISE EXCEPTION 'external incident maker and checker must differ' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS external_incident_approval_guard ON rwa.external_incident_approvals;
CREATE TRIGGER external_incident_approval_guard
BEFORE INSERT ON rwa.external_incident_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.enforce_external_incident_approval();

DROP TRIGGER IF EXISTS external_incident_approvals_append_only_guard ON rwa.external_incident_approvals;
CREATE TRIGGER external_incident_approvals_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.external_incident_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE INDEX IF NOT EXISTS external_incident_queue_idx
  ON rwa.external_reconciliation_incidents(tenant_id,product_id,status,severity,opened_at);
