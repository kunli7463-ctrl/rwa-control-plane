CREATE SCHEMA IF NOT EXISTS rwa;

CREATE TABLE IF NOT EXISTS rwa.institutions (
  id text PRIMARY KEY,
  legal_name text NOT NULL,
  jurisdiction text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
  public_key_pem text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rwa.products (
  id text PRIMARY KEY,
  name text NOT NULL,
  jurisdiction text NOT NULL,
  issuer_id text NOT NULL REFERENCES rwa.institutions(id),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  status text NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'PAUSED', 'CLOSED')),
  rule_version integer NOT NULL CHECK (rule_version > 0),
  rules jsonb NOT NULL,
  row_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rwa.product_role_assignments (
  product_id text NOT NULL REFERENCES rwa.products(id),
  role text NOT NULL CHECK (role IN ('issuer', 'distributor', 'credential_issuer', 'fund_administrator', 'custodian', 'transfer_agent', 'cash_provider')),
  institution_id text NOT NULL REFERENCES rwa.institutions(id),
  effective_at timestamptz NOT NULL,
  ended_at timestamptz,
  PRIMARY KEY (product_id, role, effective_at),
  CHECK (ended_at IS NULL OR ended_at > effective_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS product_role_active_unique
  ON rwa.product_role_assignments(product_id, role)
  WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS rwa.credentials (
  id text PRIMARY KEY,
  product_id text NOT NULL REFERENCES rwa.products(id),
  issuer_id text NOT NULL REFERENCES rwa.institutions(id),
  subject_ref text NOT NULL,
  investor_class text NOT NULL,
  jurisdiction text NOT NULL,
  max_units numeric(78, 0) NOT NULL CHECK (max_units > 0),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'RESTRICTED_EXIT', 'FROZEN', 'EXPIRED')),
  restriction_reason text,
  signed_payload jsonb NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS credential_subject_product_idx
  ON rwa.credentials(product_id, subject_ref, status);

CREATE TABLE IF NOT EXISTS rwa.evidence_envelopes (
  id text PRIMARY KEY,
  product_id text NOT NULL REFERENCES rwa.products(id),
  data_type text NOT NULL CHECK (data_type IN ('nav', 'custody_balance', 'legal_register', 'cash_state')),
  source_institution_id text NOT NULL REFERENCES rwa.institutions(id),
  trust_tier text NOT NULL,
  schema_version text NOT NULL,
  effective_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (expires_at > effective_at)
);

CREATE INDEX IF NOT EXISTS evidence_current_idx
  ON rwa.evidence_envelopes(product_id, data_type, effective_at DESC)
  WHERE status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS rwa.transaction_intents (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  idempotency_key text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  transaction_type text NOT NULL CHECK (transaction_type IN ('SUBSCRIBE', 'TRANSFER', 'REDEEM')),
  current_state text NOT NULL CHECK (current_state IN ('REQUESTED', 'POLICY_CHECKED', 'CASH_RESERVED', 'REGISTER_PENDING', 'REQUIRES_REVIEW', 'PENDING_APPROVAL', 'SETTLED', 'REPLACED', 'CANCELLED', 'REJECTED')),
  rule_version integer NOT NULL CHECK (rule_version > 0),
  nav_evidence_id text REFERENCES rwa.evidence_envelopes(id),
  policy_snapshot_hash text NOT NULL CHECK (policy_snapshot_hash ~ '^[0-9a-f]{64}$'),
  private_payload_ciphertext bytea NOT NULL CHECK (octet_length(private_payload_ciphertext) > 0),
  row_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS rwa.transaction_state_history (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  transaction_id text NOT NULL REFERENCES rwa.transaction_intents(id),
  from_state text,
  to_state text NOT NULL,
  reason_code text,
  actor_ref text,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS transaction_history_idx
  ON rwa.transaction_state_history(transaction_id, sequence_id);

CREATE TABLE IF NOT EXISTS rwa.ledger_accounts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  owner_ref text NOT NULL,
  asset_code text NOT NULL,
  account_type text NOT NULL CHECK (account_type IN ('INVESTOR', 'ISSUER', 'TREASURY', 'CASH_CLEARING', 'FEE')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, product_id, owner_ref, asset_code, account_type)
);

CREATE TABLE IF NOT EXISTS rwa.ledger_batches (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.transaction_intents(id),
  status text NOT NULL CHECK (status IN ('DRAFT', 'POSTED')),
  entry_count integer NOT NULL CHECK (entry_count >= 2),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  posted_at timestamptz
);

CREATE TABLE IF NOT EXISTS rwa.ledger_entries (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  batch_id text NOT NULL REFERENCES rwa.ledger_batches(id),
  account_id text NOT NULL REFERENCES rwa.ledger_accounts(id),
  asset_code text NOT NULL,
  signed_delta numeric(78, 0) NOT NULL CHECK (signed_delta <> 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (batch_id, account_id, asset_code)
);

CREATE INDEX IF NOT EXISTS ledger_account_entries_idx
  ON rwa.ledger_entries(account_id, sequence_id);

CREATE OR REPLACE FUNCTION rwa.assert_balanced_batch() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  unbalanced_count integer;
  actual_count integer;
BEGIN
  IF OLD.status = 'POSTED' THEN
    RAISE EXCEPTION 'posted ledger batch % is immutable', OLD.id USING ERRCODE = '55000';
  END IF;
  IF NEW.status <> 'POSTED' THEN
    RETURN NEW;
  END IF;
  SELECT count(*) INTO actual_count FROM rwa.ledger_entries WHERE batch_id = NEW.id;
  IF actual_count <> NEW.entry_count THEN
    RAISE EXCEPTION 'ledger batch % entry count mismatch', NEW.id USING ERRCODE = '23514';
  END IF;
  SELECT count(*) INTO unbalanced_count
  FROM (
    SELECT asset_code
    FROM rwa.ledger_entries
    WHERE batch_id = NEW.id
    GROUP BY asset_code
    HAVING sum(signed_delta) <> 0
  ) broken;
  IF unbalanced_count <> 0 THEN
    RAISE EXCEPTION 'ledger batch % is not balanced', NEW.id USING ERRCODE = '23514';
  END IF;
  NEW.posted_at := clock_timestamp();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS ledger_batch_balance_guard ON rwa.ledger_batches;
CREATE TRIGGER ledger_batch_balance_guard
BEFORE UPDATE OF status ON rwa.ledger_batches
FOR EACH ROW EXECUTE FUNCTION rwa.assert_balanced_batch();

CREATE OR REPLACE FUNCTION rwa.validate_ledger_entry() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  batch_status text;
  account_asset text;
BEGIN
  SELECT status INTO batch_status FROM rwa.ledger_batches WHERE id = NEW.batch_id FOR UPDATE;
  IF batch_status IS NULL THEN
    RAISE EXCEPTION 'ledger batch % does not exist', NEW.batch_id USING ERRCODE = '23503';
  END IF;
  IF batch_status <> 'DRAFT' THEN
    RAISE EXCEPTION 'ledger batch % is not open for entries', NEW.batch_id USING ERRCODE = '55000';
  END IF;
  SELECT asset_code INTO account_asset FROM rwa.ledger_accounts WHERE id = NEW.account_id;
  IF account_asset IS DISTINCT FROM NEW.asset_code THEN
    RAISE EXCEPTION 'ledger account % asset does not match entry asset', NEW.account_id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS ledger_entry_validation_guard ON rwa.ledger_entries;
CREATE TRIGGER ledger_entry_validation_guard
BEFORE INSERT ON rwa.ledger_entries
FOR EACH ROW EXECUTE FUNCTION rwa.validate_ledger_entry();

CREATE OR REPLACE FUNCTION rwa.reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TABLE IF NOT EXISTS rwa.cash_confirmations (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  source_institution_id text NOT NULL REFERENCES rwa.institutions(id),
  state text NOT NULL CHECK (state IN ('RESERVED', 'CONFIRMED', 'RELEASED', 'FAILED')),
  external_reference text,
  signed_receipt jsonb,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rwa.exception_cases (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.transaction_intents(id),
  product_id text NOT NULL REFERENCES rwa.products(id),
  status text NOT NULL CHECK (status IN ('OPEN', 'PENDING_APPROVAL', 'RESOLVED_RETRIED', 'RESOLVED_CANCELLED')),
  failure_stage text NOT NULL,
  reason_code text NOT NULL,
  replacement_transaction_id text REFERENCES rwa.transaction_intents(id),
  row_version bigint NOT NULL DEFAULT 0,
  opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS rwa.approval_records (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  exception_id text NOT NULL REFERENCES rwa.exception_cases(id),
  role text NOT NULL CHECK (role IN ('MAKER', 'CHECKER')),
  actor_ref text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('RETRY', 'CANCEL', 'APPROVE', 'REJECT')),
  signature text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (exception_id, role),
  CHECK ((role = 'MAKER' AND decision IN ('RETRY', 'CANCEL')) OR
         (role = 'CHECKER' AND decision IN ('APPROVE', 'REJECT')))
);

CREATE OR REPLACE FUNCTION rwa.enforce_maker_checker_separation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  maker_ref text;
BEGIN
  IF NEW.role <> 'CHECKER' THEN
    RETURN NEW;
  END IF;
  SELECT actor_ref INTO maker_ref
  FROM rwa.approval_records
  WHERE exception_id = NEW.exception_id AND role = 'MAKER'
  FOR UPDATE;
  IF maker_ref IS NULL THEN
    RAISE EXCEPTION 'checker approval requires a maker proposal' USING ERRCODE = '23514';
  END IF;
  IF maker_ref = NEW.actor_ref THEN
    RAISE EXCEPTION 'maker and checker must be different actors' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS maker_checker_guard ON rwa.approval_records;
CREATE TRIGGER maker_checker_guard
BEFORE INSERT ON rwa.approval_records
FOR EACH ROW EXECUTE FUNCTION rwa.enforce_maker_checker_separation();

CREATE TABLE IF NOT EXISTS rwa.audit_events (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  event_type text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  metadata jsonb NOT NULL,
  previous_hash text,
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS audit_aggregate_idx
  ON rwa.audit_events(tenant_id, aggregate_type, aggregate_id, sequence_id);

CREATE UNIQUE INDEX IF NOT EXISTS audit_chain_single_successor
  ON rwa.audit_events(tenant_id, aggregate_type, aggregate_id, COALESCE(previous_hash, ''));

CREATE UNIQUE INDEX IF NOT EXISTS audit_event_hash_unique
  ON rwa.audit_events(event_hash);

CREATE TABLE IF NOT EXISTS rwa.outbox_events (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  topic text NOT NULL,
  aggregate_id text NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'CLAIMED', 'PUBLISHED', 'FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  claimed_by text,
  claimed_at timestamptz,
  published_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS outbox_dispatch_idx
  ON rwa.outbox_events(status, available_at, created_at)
  WHERE status IN ('PENDING', 'FAILED');

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['transaction_state_history', 'ledger_entries', 'audit_events'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS append_only_guard ON rwa.%I', table_name);
    EXECUTE format('CREATE TRIGGER append_only_guard BEFORE UPDATE OR DELETE ON rwa.%I FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation()', table_name);
  END LOOP;
END;
$$;
