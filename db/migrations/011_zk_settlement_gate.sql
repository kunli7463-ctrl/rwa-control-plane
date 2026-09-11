CREATE TABLE IF NOT EXISTS rwa.proof_circuit_versions (
  circuit_id text NOT NULL,
  circuit_version text NOT NULL,
  protocol text NOT NULL CHECK (protocol='groth16'),
  curve text NOT NULL CHECK (curve='bn128'),
  verification_key_hash text NOT NULL CHECK (verification_key_hash ~ '^[0-9a-f]{64}$'),
  artifact_manifest_hash text NOT NULL CHECK (artifact_manifest_hash ~ '^[0-9a-f]{64}$'),
  public_signal_order jsonb NOT NULL CHECK (jsonb_typeof(public_signal_order)='array'),
  status text NOT NULL CHECK (status IN ('CANDIDATE','ACTIVE','SUSPENDED','RETIRED')),
  activated_at timestamptz,
  retired_at timestamptz,
  PRIMARY KEY (circuit_id,circuit_version),
  CHECK ((status='ACTIVE' AND activated_at IS NOT NULL) OR status<>'ACTIVE')
);

CREATE TABLE IF NOT EXISTS rwa.zk_merkle_roots (
  context_id numeric(78,0) NOT NULL,
  merkle_root numeric(78,0) NOT NULL,
  tree_size bigint NOT NULL CHECK (tree_size>=0),
  status text NOT NULL CHECK (status IN ('CURRENT','HISTORICAL','REVOKED')),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz,
  source_reference text NOT NULL,
  PRIMARY KEY (context_id,merkle_root),
  CHECK (expires_at IS NULL OR expires_at>observed_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS zk_merkle_current_context_unique
  ON rwa.zk_merkle_roots(context_id) WHERE status='CURRENT';

CREATE TABLE IF NOT EXISTS rwa.zk_proof_receipts (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.transaction_intents(id),
  tenant_id text NOT NULL,
  circuit_id text NOT NULL,
  circuit_version text NOT NULL,
  context_id numeric(78,0) NOT NULL,
  merkle_root numeric(78,0) NOT NULL,
  verification_key_hash text NOT NULL CHECK (verification_key_hash ~ '^[0-9a-f]{64}$'),
  proof_hash text NOT NULL CHECK (proof_hash ~ '^[0-9a-f]{64}$'),
  public_signals_hash text NOT NULL CHECK (public_signals_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status='VERIFIED'),
  verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (circuit_id,circuit_version) REFERENCES rwa.proof_circuit_versions(circuit_id,circuit_version),
  FOREIGN KEY (context_id,merkle_root) REFERENCES rwa.zk_merkle_roots(context_id,merkle_root)
);

CREATE TABLE IF NOT EXISTS rwa.zk_spent_nullifiers (
  context_id numeric(78,0) NOT NULL,
  nullifier numeric(78,0) NOT NULL,
  proof_receipt_id text NOT NULL REFERENCES rwa.zk_proof_receipts(id),
  spent_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (context_id,nullifier)
);

CREATE TABLE IF NOT EXISTS rwa.zk_output_commitments (
  proof_receipt_id text NOT NULL REFERENCES rwa.zk_proof_receipts(id),
  output_index smallint NOT NULL CHECK (output_index IN (0,1)),
  commitment_x numeric(78,0) NOT NULL,
  commitment_y numeric(78,0) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (proof_receipt_id,output_index),
  UNIQUE (commitment_x,commitment_y)
);

CREATE INDEX IF NOT EXISTS zk_receipts_tenant_context_idx
  ON rwa.zk_proof_receipts(tenant_id,context_id,verified_at);

DROP TRIGGER IF EXISTS zk_proof_receipts_append_only_guard ON rwa.zk_proof_receipts;
CREATE TRIGGER zk_proof_receipts_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_proof_receipts
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

DROP TRIGGER IF EXISTS zk_spent_nullifiers_append_only_guard ON rwa.zk_spent_nullifiers;
CREATE TRIGGER zk_spent_nullifiers_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_spent_nullifiers
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

DROP TRIGGER IF EXISTS zk_output_commitments_append_only_guard ON rwa.zk_output_commitments;
CREATE TRIGGER zk_output_commitments_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.zk_output_commitments
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

