CREATE TABLE IF NOT EXISTS rwa.callback_evidence_records (
  callback_id text PRIMARY KEY REFERENCES rwa.callback_receipts(callback_id),
  evidence_id text NOT NULL UNIQUE,
  product_id text NOT NULL REFERENCES rwa.products(id),
  evidence_type text NOT NULL CHECK (evidence_type IN ('legal_register', 'cash_state', 'custody_balance')),
  source_institution_id text NOT NULL REFERENCES rwa.institutions(id),
  subject_type text NOT NULL CHECK (subject_type IN ('TRANSACTION', 'POSITION')),
  subject_ref text NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  source_signature text NOT NULL,
  effective_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (expires_at > effective_at)
);

CREATE OR REPLACE FUNCTION rwa.validate_callback_application_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'callback applications cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.status <> 'BUFFERED' OR NEW.status <> 'APPLIED'
     OR NEW.callback_id IS DISTINCT FROM OLD.callback_id THEN
    RAISE EXCEPTION 'invalid callback application transition' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS rwa.external_callback_confirmations (
  callback_id text PRIMARY KEY REFERENCES rwa.callback_receipts(callback_id),
  transaction_id text REFERENCES rwa.transaction_intents(id),
  product_id text NOT NULL REFERENCES rwa.products(id),
  channel text NOT NULL CHECK (channel IN ('REGISTER', 'CASH', 'CUSTODY')),
  outcome text NOT NULL CHECK (outcome IN ('CONFIRMED', 'REJECTED', 'PERMANENT_FAILURE')),
  reconciliation_status text NOT NULL CHECK (reconciliation_status IN ('CONTEXT_MATCHED', 'MISMATCH', 'NOT_APPLICABLE')),
  mismatch_reason text,
  evidence_id text NOT NULL REFERENCES rwa.callback_evidence_records(evidence_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((reconciliation_status='MISMATCH' AND mismatch_reason IS NOT NULL)
      OR (reconciliation_status<>'MISMATCH' AND mismatch_reason IS NULL))
);

CREATE INDEX IF NOT EXISTS external_confirmation_transaction_idx
  ON rwa.external_callback_confirmations(transaction_id,channel,created_at DESC)
  WHERE transaction_id IS NOT NULL;

DROP TRIGGER IF EXISTS callback_evidence_append_only_guard ON rwa.callback_evidence_records;
CREATE TRIGGER callback_evidence_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.callback_evidence_records
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

DROP TRIGGER IF EXISTS external_callback_confirmation_append_only_guard ON rwa.external_callback_confirmations;
CREATE TRIGGER external_callback_confirmation_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.external_callback_confirmations
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE OR REPLACE VIEW rwa.transaction_external_reconciliation AS
WITH latest AS (
  SELECT DISTINCT ON (c.transaction_id,c.channel)
    c.transaction_id,c.channel,c.outcome,c.reconciliation_status,c.mismatch_reason,c.evidence_id,c.created_at
  FROM rwa.external_callback_confirmations c
  WHERE c.transaction_id IS NOT NULL
  ORDER BY c.transaction_id,c.channel,c.created_at DESC,c.callback_id DESC
)
SELECT t.id AS transaction_id,t.tenant_id,t.product_id,t.current_state,
       max(l.outcome) FILTER (WHERE l.channel='REGISTER') AS register_outcome,
       max(l.outcome) FILTER (WHERE l.channel='CASH') AS cash_outcome,
       CASE
         WHEN bool_or(l.reconciliation_status='MISMATCH') THEN 'MISMATCH'
         WHEN count(*) FILTER (WHERE l.channel IN ('REGISTER','CASH'))=2
              AND bool_and(l.outcome='CONFIRMED') FILTER (WHERE l.channel IN ('REGISTER','CASH')) THEN 'EXTERNALLY_CONFIRMED'
         WHEN bool_or(l.outcome IN ('REJECTED','PERMANENT_FAILURE')) THEN 'EXTERNAL_FAILURE'
         ELSE 'AWAITING_CONFIRMATION'
       END AS external_status
FROM rwa.transaction_intents t
LEFT JOIN latest l ON l.transaction_id=t.id
GROUP BY t.id,t.tenant_id,t.product_id,t.current_state;
