CREATE TABLE IF NOT EXISTS rwa.transaction_economic_commitments (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  commitment_version text NOT NULL CHECK (commitment_version='HMAC-SHA256-v1'),
  key_id text NOT NULL,
  asset_code text NOT NULL,
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  units_commitment text NOT NULL CHECK (units_commitment ~ '^[0-9a-f]{64}$'),
  cash_amount_commitment text NOT NULL CHECK (cash_amount_commitment ~ '^[0-9a-f]{64}$'),
  fee_amount_commitment text NOT NULL CHECK (fee_amount_commitment ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS transaction_economic_commitments_append_only_guard ON rwa.transaction_economic_commitments;
CREATE TRIGGER transaction_economic_commitments_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.transaction_economic_commitments
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

ALTER TABLE rwa.external_callback_confirmations
  DROP CONSTRAINT IF EXISTS external_callback_confirmations_reconciliation_status_check;
ALTER TABLE rwa.external_callback_confirmations
  ADD CONSTRAINT external_callback_confirmations_reconciliation_status_check
  CHECK (reconciliation_status IN ('FULLY_MATCHED', 'CONTEXT_MATCHED', 'MISMATCH', 'NOT_APPLICABLE'));

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
              AND bool_and(l.outcome='CONFIRMED') FILTER (WHERE l.channel IN ('REGISTER','CASH'))
              AND bool_and(l.reconciliation_status='FULLY_MATCHED') FILTER (WHERE l.channel IN ('REGISTER','CASH'))
           THEN 'EXTERNALLY_CONFIRMED'
         WHEN bool_or(l.outcome IN ('REJECTED','PERMANENT_FAILURE')) THEN 'EXTERNAL_FAILURE'
         ELSE 'AWAITING_CONFIRMATION'
       END AS external_status
FROM rwa.transaction_intents t
LEFT JOIN latest l ON l.transaction_id=t.id
GROUP BY t.id,t.tenant_id,t.product_id,t.current_state;
