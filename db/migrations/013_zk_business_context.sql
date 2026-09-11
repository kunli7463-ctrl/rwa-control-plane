CREATE TABLE IF NOT EXISTS rwa.zk_product_contexts (
  product_id text NOT NULL REFERENCES rwa.products(id),
  circuit_id text NOT NULL,
  circuit_version text NOT NULL,
  context_id numeric(78,0) NOT NULL UNIQUE,
  asset_type numeric(10,0) NOT NULL CHECK (asset_type>=0 AND asset_type<4294967296),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  PRIMARY KEY (product_id,circuit_id,circuit_version),
  FOREIGN KEY (circuit_id,circuit_version)
    REFERENCES rwa.proof_circuit_versions(circuit_id,circuit_version),
  CHECK (retired_at IS NULL OR retired_at>created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS zk_product_contexts_one_current
  ON rwa.zk_product_contexts(product_id) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS rwa.zk_execution_instructions (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  tenant_id text NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  fee numeric(20,0) NOT NULL CHECK (fee>=0 AND fee<18446744073709551616),
  recipient numeric(78,0) NOT NULL
    CHECK (recipient>=0 AND recipient<21888242871839275222246405745257275088548364400416034343698204186575808495617),
  relayer numeric(78,0) NOT NULL
    CHECK (relayer>=0 AND relayer<21888242871839275222246405745257275088548364400416034343698204186575808495617),
  authorized_by text NOT NULL,
  authorized_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS zk_execution_instructions_append_only_guard ON rwa.zk_execution_instructions;
CREATE TRIGGER zk_execution_instructions_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_execution_instructions
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE OR REPLACE FUNCTION rwa.guard_zk_product_context() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK product contexts cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
     OR NEW.retired_at<=OLD.created_at
     OR NEW.product_id IS DISTINCT FROM OLD.product_id
     OR NEW.circuit_id IS DISTINCT FROM OLD.circuit_id
     OR NEW.circuit_version IS DISTINCT FROM OLD.circuit_version
     OR NEW.context_id IS DISTINCT FROM OLD.context_id
     OR NEW.asset_type IS DISTINCT FROM OLD.asset_type
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'invalid ZK product context retirement or immutable field mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_product_context_guard ON rwa.zk_product_contexts;
CREATE TRIGGER zk_product_context_guard
BEFORE UPDATE OR DELETE ON rwa.zk_product_contexts
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_product_context();
