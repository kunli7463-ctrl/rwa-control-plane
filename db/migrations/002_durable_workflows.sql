ALTER TABLE rwa.ledger_batches ALTER COLUMN transaction_id DROP NOT NULL;
ALTER TABLE rwa.ledger_batches ADD COLUMN source_type text NOT NULL DEFAULT 'TRANSACTION';
ALTER TABLE rwa.ledger_batches ADD CONSTRAINT ledger_batch_source_check CHECK (
  (source_type = 'TRANSACTION' AND transaction_id IS NOT NULL) OR
  (source_type = 'OPENING' AND transaction_id IS NULL)
);

CREATE TABLE rwa.register_accounts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  owner_ref text NOT NULL,
  asset_code text NOT NULL,
  account_type text NOT NULL CHECK (account_type IN ('INVESTOR', 'TREASURY')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, product_id, owner_ref, asset_code, account_type)
);

CREATE TABLE rwa.register_batches (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.transaction_intents(id),
  asset_code text NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT', 'POSTED')),
  entry_count integer NOT NULL CHECK (entry_count >= 2),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  posted_at timestamptz
);

CREATE TABLE rwa.register_entries (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  batch_id text NOT NULL REFERENCES rwa.register_batches(id),
  account_id text NOT NULL REFERENCES rwa.register_accounts(id),
  asset_code text NOT NULL,
  signed_delta numeric(78, 0) NOT NULL CHECK (signed_delta <> 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (batch_id, account_id, asset_code)
);

CREATE INDEX register_account_entries_idx
  ON rwa.register_entries(account_id, sequence_id);

CREATE OR REPLACE FUNCTION rwa.validate_register_entry() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  batch_status text;
  batch_asset text;
  account_asset text;
BEGIN
  SELECT status, asset_code INTO batch_status, batch_asset
  FROM rwa.register_batches WHERE id = NEW.batch_id FOR UPDATE;
  IF batch_status IS NULL THEN
    RAISE EXCEPTION 'register batch % does not exist', NEW.batch_id USING ERRCODE = '23503';
  END IF;
  IF batch_status <> 'DRAFT' THEN
    RAISE EXCEPTION 'register batch % is not open for entries', NEW.batch_id USING ERRCODE = '55000';
  END IF;
  SELECT asset_code INTO account_asset FROM rwa.register_accounts WHERE id = NEW.account_id;
  IF batch_asset IS DISTINCT FROM NEW.asset_code OR account_asset IS DISTINCT FROM NEW.asset_code THEN
    RAISE EXCEPTION 'register entry asset mismatch' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER register_entry_validation_guard
BEFORE INSERT ON rwa.register_entries
FOR EACH ROW EXECUTE FUNCTION rwa.validate_register_entry();

CREATE OR REPLACE FUNCTION rwa.assert_register_batch() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  actual_count integer;
  total_delta numeric(78, 0);
  mismatch_count integer;
BEGIN
  IF OLD.status = 'POSTED' THEN
    RAISE EXCEPTION 'posted register batch % is immutable', OLD.id USING ERRCODE = '55000';
  END IF;
  IF NEW.status <> 'POSTED' THEN
    RETURN NEW;
  END IF;

  SELECT count(*), COALESCE(sum(signed_delta), 0)
  INTO actual_count, total_delta
  FROM rwa.register_entries WHERE batch_id = NEW.id;
  IF actual_count <> NEW.entry_count OR total_delta <> 0 THEN
    RAISE EXCEPTION 'register batch % is incomplete or unbalanced', NEW.id USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO mismatch_count
  FROM (
    WITH asset_moves AS (
      SELECT a.owner_ref, sum(e.signed_delta) AS delta
      FROM rwa.ledger_batches b
      JOIN rwa.ledger_entries e ON e.batch_id = b.id
      JOIN rwa.ledger_accounts a ON a.id = e.account_id
      WHERE b.transaction_id = NEW.transaction_id AND e.asset_code = NEW.asset_code
      GROUP BY a.owner_ref
    ), register_moves AS (
      SELECT a.owner_ref, sum(e.signed_delta) AS delta
      FROM rwa.register_entries e
      JOIN rwa.register_accounts a ON a.id = e.account_id
      WHERE e.batch_id = NEW.id
      GROUP BY a.owner_ref
    )
    SELECT COALESCE(x.owner_ref, r.owner_ref)
    FROM asset_moves x FULL JOIN register_moves r USING (owner_ref)
    WHERE x.delta IS DISTINCT FROM r.delta
  ) mismatches;
  IF mismatch_count <> 0 THEN
    RAISE EXCEPTION 'register batch % does not mirror the asset ledger', NEW.id USING ERRCODE = '23514';
  END IF;
  NEW.posted_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER register_batch_guard
BEFORE UPDATE OF status ON rwa.register_batches
FOR EACH ROW EXECUTE FUNCTION rwa.assert_register_batch();

CREATE TABLE rwa.transaction_receipts (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  receipt jsonb NOT NULL,
  receipt_hash text NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['register_entries', 'transaction_receipts'] LOOP
    EXECUTE format('CREATE TRIGGER append_only_guard BEFORE UPDATE OR DELETE ON rwa.%I FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation()', table_name);
  END LOOP;
END;
$$;
