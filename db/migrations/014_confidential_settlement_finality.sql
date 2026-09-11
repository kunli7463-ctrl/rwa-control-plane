ALTER TABLE rwa.transaction_intents
  ADD COLUMN IF NOT EXISTS settlement_rail text NOT NULL DEFAULT 'REGISTERED';

ALTER TABLE rwa.transaction_intents
  DROP CONSTRAINT IF EXISTS transaction_intents_current_state_check;

ALTER TABLE rwa.transaction_intents
  ADD CONSTRAINT transaction_intents_current_state_check
  CHECK (current_state IN (
    'REQUESTED', 'POLICY_CHECKED', 'CASH_RESERVED', 'REGISTER_PENDING',
    'PROOF_PENDING', 'REQUIRES_REVIEW', 'PENDING_APPROVAL', 'SETTLED',
    'REPLACED', 'CANCELLED', 'REJECTED'
  ));

ALTER TABLE rwa.transaction_intents
  DROP CONSTRAINT IF EXISTS transaction_intents_settlement_rail_check;

ALTER TABLE rwa.transaction_intents
  ADD CONSTRAINT transaction_intents_settlement_rail_check
  CHECK (settlement_rail IN ('REGISTERED', 'CONFIDENTIAL_NOTE'));

ALTER TABLE rwa.transaction_intents
  DROP CONSTRAINT IF EXISTS transaction_intents_confidential_transfer_check;

ALTER TABLE rwa.transaction_intents
  ADD CONSTRAINT transaction_intents_confidential_transfer_check
  CHECK (settlement_rail <> 'CONFIDENTIAL_NOTE' OR transaction_type = 'TRANSFER');

CREATE TABLE IF NOT EXISTS rwa.zk_settlements (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  proof_receipt_id text NOT NULL UNIQUE REFERENCES rwa.zk_proof_receipts(id),
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  context_id numeric(78,0) NOT NULL,
  merkle_root numeric(78,0) NOT NULL,
  finality_domain text NOT NULL CHECK (finality_domain = 'CONFIDENTIAL_NOTE_LEDGER'),
  finality_status text NOT NULL CHECK (finality_status = 'FINAL'),
  legal_register_applied boolean NOT NULL DEFAULT false CHECK (legal_register_applied = false),
  settled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS zk_settlements_product_time_idx
  ON rwa.zk_settlements(tenant_id, product_id, settled_at DESC);

CREATE OR REPLACE FUNCTION rwa.guard_zk_settlement_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  tx rwa.transaction_intents%ROWTYPE;
  receipt rwa.zk_proof_receipts%ROWTYPE;
BEGIN
  SELECT * INTO tx FROM rwa.transaction_intents WHERE id=NEW.transaction_id FOR SHARE;
  IF tx.id IS NULL
     OR tx.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR tx.product_id IS DISTINCT FROM NEW.product_id
     OR tx.transaction_type <> 'TRANSFER'
     OR tx.settlement_rail <> 'CONFIDENTIAL_NOTE'
     OR tx.current_state <> 'SETTLED' THEN
    RAISE EXCEPTION 'invalid confidential settlement transaction boundary' USING ERRCODE='23514';
  END IF;

  SELECT * INTO receipt FROM rwa.zk_proof_receipts WHERE id=NEW.proof_receipt_id FOR SHARE;
  IF receipt.id IS NULL
     OR receipt.transaction_id IS DISTINCT FROM NEW.transaction_id
     OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR receipt.context_id IS DISTINCT FROM NEW.context_id
     OR receipt.merkle_root IS DISTINCT FROM NEW.merkle_root
     OR receipt.status <> 'VERIFIED' THEN
    RAISE EXCEPTION 'invalid confidential settlement proof receipt boundary' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_settlement_insert_guard ON rwa.zk_settlements;
CREATE TRIGGER zk_settlement_insert_guard
BEFORE INSERT ON rwa.zk_settlements
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_settlement_insert();

DROP TRIGGER IF EXISTS zk_settlements_append_only_guard ON rwa.zk_settlements;
CREATE TRIGGER zk_settlements_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_settlements
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION rwa.guard_transaction_settlement_rail() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.settlement_rail IS DISTINCT FROM OLD.settlement_rail THEN
    RAISE EXCEPTION 'transaction settlement rail is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.current_state='PROOF_PENDING' AND NEW.settlement_rail<>'CONFIDENTIAL_NOTE' THEN
    RAISE EXCEPTION 'only confidential note transactions can await a proof' USING ERRCODE='23514';
  END IF;
  IF NEW.settlement_rail='CONFIDENTIAL_NOTE' AND NEW.current_state IS DISTINCT FROM OLD.current_state
     AND NOT (
       (OLD.current_state='REQUESTED' AND NEW.current_state IN ('POLICY_CHECKED','REJECTED')) OR
       (OLD.current_state='POLICY_CHECKED' AND NEW.current_state IN ('PROOF_PENDING','REJECTED')) OR
       (OLD.current_state='PROOF_PENDING' AND NEW.current_state IN ('SETTLED','REQUIRES_REVIEW','REJECTED')) OR
       (OLD.current_state='REQUIRES_REVIEW' AND NEW.current_state IN ('PENDING_APPROVAL','CANCELLED')) OR
       (OLD.current_state='PENDING_APPROVAL' AND NEW.current_state IN ('REQUIRES_REVIEW','REPLACED','CANCELLED'))
     ) THEN
    RAISE EXCEPTION 'invalid confidential transaction state transition % -> %', OLD.current_state, NEW.current_state
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS transaction_settlement_rail_guard ON rwa.transaction_intents;
CREATE TRIGGER transaction_settlement_rail_guard
BEFORE UPDATE OF current_state,settlement_rail ON rwa.transaction_intents
FOR EACH ROW EXECUTE FUNCTION rwa.guard_transaction_settlement_rail();

CREATE OR REPLACE FUNCTION rwa.require_confidential_settlement_finality() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.settlement_rail='CONFIDENTIAL_NOTE' AND NEW.current_state='SETTLED'
     AND NOT EXISTS (SELECT 1 FROM rwa.zk_settlements z WHERE z.transaction_id=NEW.id) THEN
    RAISE EXCEPTION 'settled confidential transaction has no atomic ZK settlement record' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS confidential_settlement_finality_guard ON rwa.transaction_intents;
CREATE CONSTRAINT TRIGGER confidential_settlement_finality_guard
AFTER INSERT OR UPDATE OF current_state ON rwa.transaction_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION rwa.require_confidential_settlement_finality();
