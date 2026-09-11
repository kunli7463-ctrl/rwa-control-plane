ALTER TABLE rwa.zk_output_commitments
  ADD COLUMN IF NOT EXISTS context_id numeric(78,0);

ALTER TABLE rwa.zk_output_commitments DISABLE TRIGGER zk_output_commitments_append_only_guard;
UPDATE rwa.zk_output_commitments o
SET context_id=r.context_id
FROM rwa.zk_proof_receipts r
WHERE r.id=o.proof_receipt_id AND o.context_id IS NULL;
ALTER TABLE rwa.zk_output_commitments ENABLE TRIGGER zk_output_commitments_append_only_guard;

ALTER TABLE rwa.zk_output_commitments
  ALTER COLUMN context_id SET NOT NULL;

ALTER TABLE rwa.zk_output_commitments
  DROP CONSTRAINT IF EXISTS zk_output_commitments_commitment_x_commitment_y_key;

ALTER TABLE rwa.zk_output_commitments
  ADD CONSTRAINT zk_output_commitments_context_commitment_unique
  UNIQUE (context_id,commitment_x,commitment_y);

ALTER TABLE rwa.zk_output_commitments
  DROP CONSTRAINT IF EXISTS zk_output_commitments_context_fk;

CREATE OR REPLACE FUNCTION rwa.guard_zk_output_commitment_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM rwa.zk_proof_receipts r
    WHERE r.id=NEW.proof_receipt_id AND r.context_id=NEW.context_id AND r.status='VERIFIED'
  ) THEN
    RAISE EXCEPTION 'output commitment context does not match its verified proof receipt'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_output_commitment_insert_guard ON rwa.zk_output_commitments;
CREATE TRIGGER zk_output_commitment_insert_guard
BEFORE INSERT ON rwa.zk_output_commitments
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_output_commitment_insert();

ALTER TABLE rwa.zk_execution_instructions
  ADD COLUMN IF NOT EXISTS expires_at timestamptz;

ALTER TABLE rwa.zk_execution_instructions DISABLE TRIGGER zk_execution_instructions_append_only_guard;
UPDATE rwa.zk_execution_instructions
SET expires_at=authorized_at + interval '15 minutes'
WHERE expires_at IS NULL;
ALTER TABLE rwa.zk_execution_instructions ENABLE TRIGGER zk_execution_instructions_append_only_guard;

ALTER TABLE rwa.zk_execution_instructions
  ALTER COLUMN expires_at SET DEFAULT (clock_timestamp() + interval '15 minutes'),
  ALTER COLUMN expires_at SET NOT NULL;

ALTER TABLE rwa.zk_execution_instructions
  DROP CONSTRAINT IF EXISTS zk_execution_instructions_expiry_check;

ALTER TABLE rwa.zk_execution_instructions
  ADD CONSTRAINT zk_execution_instructions_expiry_check
  CHECK (expires_at > authorized_at);

CREATE OR REPLACE FUNCTION rwa.guard_zk_merkle_root_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK Merkle roots cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF NEW.context_id IS DISTINCT FROM OLD.context_id
     OR NEW.merkle_root IS DISTINCT FROM OLD.merkle_root
     OR NEW.tree_size IS DISTINCT FROM OLD.tree_size
     OR NEW.observed_at IS DISTINCT FROM OLD.observed_at
     OR NEW.source_reference IS DISTINCT FROM OLD.source_reference
     OR NOT (
       (OLD.status='CURRENT' AND NEW.status IN ('HISTORICAL','REVOKED')) OR
       (OLD.status='HISTORICAL' AND NEW.status='REVOKED')
     )
     OR (NEW.status='HISTORICAL' AND NEW.expires_at IS NULL)
     OR (NEW.status='HISTORICAL' AND NEW.expires_at<=clock_timestamp())
     OR (NEW.status='REVOKED' AND NEW.expires_at IS DISTINCT FROM OLD.expires_at) THEN
    RAISE EXCEPTION 'invalid ZK Merkle root lifecycle transition or immutable field mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_merkle_root_lifecycle_guard ON rwa.zk_merkle_roots;
CREATE TRIGGER zk_merkle_root_lifecycle_guard
BEFORE UPDATE OR DELETE ON rwa.zk_merkle_roots
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_merkle_root_lifecycle();

-- Production OIDC sessions authorize by permission, not by the sandbox role map.
INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('broker','transaction.zk.prepare'),
  ('broker','transaction.zk.authorize'),
  ('broker','transaction.zk.settle'),
  ('operations','transaction.zk.settle'),
  ('operations','transaction.zk.finalize')
ON CONFLICT DO NOTHING;

-- Proof verification consumes nullifiers, but it does not by itself publish the
-- two outputs into the authoritative note tree or execute the proof-bound
-- recipient/relayer effects. Keep that intermediate fact explicit.
ALTER TABLE rwa.transaction_intents
  DROP CONSTRAINT IF EXISTS transaction_intents_current_state_check;

ALTER TABLE rwa.transaction_intents
  ADD CONSTRAINT transaction_intents_current_state_check
  CHECK (current_state IN (
    'REQUESTED', 'POLICY_CHECKED', 'CASH_RESERVED', 'REGISTER_PENDING',
    'PROOF_PENDING', 'ROOT_PENDING', 'REQUIRES_REVIEW', 'PENDING_APPROVAL', 'SETTLED',
    'REPLACED', 'CANCELLED', 'REJECTED'
  ));

ALTER TABLE rwa.zk_settlements
  ADD COLUMN IF NOT EXISTS output_merkle_root numeric(78,0),
  ADD COLUMN IF NOT EXISTS output_tree_size bigint,
  ADD COLUMN IF NOT EXISTS root_source_reference text,
  ADD COLUMN IF NOT EXISTS execution_reference text,
  ADD COLUMN IF NOT EXISTS finalized_by text,
  ADD COLUMN IF NOT EXISTS finalized_at timestamptz;

ALTER TABLE rwa.zk_settlements
  DROP CONSTRAINT IF EXISTS zk_settlements_finality_domain_check,
  DROP CONSTRAINT IF EXISTS zk_settlements_finality_status_check;

-- This project has not been deployed. Convert any synthetic pre-v15 rows away
-- from the earlier over-claimed finality label during local upgrades.
ALTER TABLE rwa.zk_settlements DISABLE TRIGGER zk_settlements_append_only_guard;
ALTER TABLE rwa.transaction_intents DISABLE TRIGGER transaction_settlement_rail_guard;
ALTER TABLE rwa.transaction_intents DISABLE TRIGGER confidential_settlement_finality_guard;
UPDATE rwa.zk_settlements
SET finality_domain='CONFIDENTIAL_PROOF_REGISTRY', finality_status='ROOT_PENDING'
WHERE finality_domain='CONFIDENTIAL_NOTE_LEDGER';
UPDATE rwa.transaction_intents
SET current_state='ROOT_PENDING', updated_at=clock_timestamp()
WHERE settlement_rail='CONFIDENTIAL_NOTE' AND current_state='SETTLED';
ALTER TABLE rwa.transaction_intents ENABLE TRIGGER confidential_settlement_finality_guard;
ALTER TABLE rwa.transaction_intents ENABLE TRIGGER transaction_settlement_rail_guard;
ALTER TABLE rwa.zk_settlements ENABLE TRIGGER zk_settlements_append_only_guard;

ALTER TABLE rwa.zk_settlements
  ADD CONSTRAINT zk_settlements_finality_domain_check
  CHECK (finality_domain IN ('CONFIDENTIAL_PROOF_REGISTRY','CONFIDENTIAL_NOTE_LEDGER')),
  ADD CONSTRAINT zk_settlements_finality_status_check
  CHECK (finality_status IN ('ROOT_PENDING','FINAL')),
  ADD CONSTRAINT zk_settlements_finality_shape_check
  CHECK (
    (finality_status='ROOT_PENDING'
      AND finality_domain='CONFIDENTIAL_PROOF_REGISTRY'
      AND output_merkle_root IS NULL AND output_tree_size IS NULL
      AND root_source_reference IS NULL AND execution_reference IS NULL
      AND finalized_by IS NULL AND finalized_at IS NULL)
    OR
    (finality_status='FINAL'
      AND finality_domain='CONFIDENTIAL_NOTE_LEDGER'
      AND output_merkle_root IS NOT NULL AND output_tree_size IS NOT NULL
      AND output_tree_size>=2 AND root_source_reference IS NOT NULL
      AND execution_reference IS NOT NULL AND finalized_by IS NOT NULL
      AND finalized_at IS NOT NULL)
  );

CREATE TABLE IF NOT EXISTS rwa.zk_root_publication_attestations (
  transaction_id text PRIMARY KEY REFERENCES rwa.zk_settlements(transaction_id),
  tenant_id text NOT NULL,
  context_id numeric(78,0) NOT NULL,
  proof_receipt_id text NOT NULL UNIQUE REFERENCES rwa.zk_proof_receipts(id),
  output_merkle_root numeric(78,0) NOT NULL,
  output_tree_size bigint NOT NULL CHECK (output_tree_size>=2),
  root_source_reference text NOT NULL,
  execution_reference text NOT NULL,
  attested_by text NOT NULL,
  attested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (context_id,output_merkle_root)
    REFERENCES rwa.zk_merkle_roots(context_id,merkle_root)
);

DROP TRIGGER IF EXISTS zk_root_publication_attestations_append_only_guard
  ON rwa.zk_root_publication_attestations;
CREATE TRIGGER zk_root_publication_attestations_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_root_publication_attestations
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION rwa.guard_zk_settlement_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK settlements cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.finality_status<>'ROOT_PENDING' OR NEW.finality_status<>'FINAL'
     OR NEW.finality_domain<>'CONFIDENTIAL_NOTE_LEDGER'
     OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
     OR NEW.proof_receipt_id IS DISTINCT FROM OLD.proof_receipt_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.product_id IS DISTINCT FROM OLD.product_id
     OR NEW.context_id IS DISTINCT FROM OLD.context_id
     OR NEW.merkle_root IS DISTINCT FROM OLD.merkle_root
     OR NEW.legal_register_applied IS DISTINCT FROM OLD.legal_register_applied
     OR NEW.settled_at IS DISTINCT FROM OLD.settled_at
     OR NEW.output_merkle_root IS NULL OR NEW.output_tree_size IS NULL
     OR NEW.root_source_reference IS NULL OR NEW.execution_reference IS NULL
     OR NEW.finalized_by IS NULL OR NEW.finalized_at IS NULL THEN
    RAISE EXCEPTION 'invalid ZK settlement lifecycle mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_settlements_append_only_guard ON rwa.zk_settlements;
CREATE TRIGGER zk_settlements_lifecycle_guard
BEFORE UPDATE OR DELETE ON rwa.zk_settlements
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_settlement_lifecycle();

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
     OR tx.current_state <> 'ROOT_PENDING'
     OR NEW.finality_domain <> 'CONFIDENTIAL_PROOF_REGISTRY'
     OR NEW.finality_status <> 'ROOT_PENDING' THEN
    RAISE EXCEPTION 'invalid confidential proof-registry boundary' USING ERRCODE='23514';
  END IF;

  SELECT * INTO receipt FROM rwa.zk_proof_receipts WHERE id=NEW.proof_receipt_id FOR SHARE;
  IF receipt.id IS NULL
     OR receipt.transaction_id IS DISTINCT FROM NEW.transaction_id
     OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR receipt.context_id IS DISTINCT FROM NEW.context_id
     OR receipt.merkle_root IS DISTINCT FROM NEW.merkle_root
     OR receipt.status <> 'VERIFIED' THEN
    RAISE EXCEPTION 'invalid confidential proof receipt boundary' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rwa.guard_transaction_settlement_rail() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.settlement_rail IS DISTINCT FROM OLD.settlement_rail THEN
    RAISE EXCEPTION 'transaction settlement rail is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.current_state IN ('PROOF_PENDING','ROOT_PENDING') AND NEW.settlement_rail<>'CONFIDENTIAL_NOTE' THEN
    RAISE EXCEPTION 'only confidential note transactions can await proof or root finality' USING ERRCODE='23514';
  END IF;
  IF NEW.settlement_rail='CONFIDENTIAL_NOTE' AND NEW.current_state IS DISTINCT FROM OLD.current_state
     AND NOT (
       (OLD.current_state='REQUESTED' AND NEW.current_state IN ('POLICY_CHECKED','REJECTED')) OR
       (OLD.current_state='POLICY_CHECKED' AND NEW.current_state IN ('PROOF_PENDING','REJECTED')) OR
       (OLD.current_state='PROOF_PENDING' AND NEW.current_state IN ('ROOT_PENDING','REQUIRES_REVIEW','REJECTED')) OR
       (OLD.current_state='ROOT_PENDING' AND NEW.current_state IN ('SETTLED','REQUIRES_REVIEW','REJECTED')) OR
       (OLD.current_state='REQUIRES_REVIEW' AND NEW.current_state IN ('PENDING_APPROVAL','CANCELLED')) OR
       (OLD.current_state='PENDING_APPROVAL' AND NEW.current_state IN ('REQUIRES_REVIEW','REPLACED','CANCELLED'))
     ) THEN
    RAISE EXCEPTION 'invalid confidential transaction state transition % -> %', OLD.current_state, NEW.current_state
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rwa.require_confidential_settlement_finality() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.settlement_rail='CONFIDENTIAL_NOTE' AND NEW.current_state='SETTLED'
     AND NOT EXISTS (
       SELECT 1 FROM rwa.zk_settlements z
       WHERE z.transaction_id=NEW.id AND z.finality_status='FINAL'
         AND z.finality_domain='CONFIDENTIAL_NOTE_LEDGER'
     ) THEN
    RAISE EXCEPTION 'settled confidential transaction has no authoritative root finality' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
