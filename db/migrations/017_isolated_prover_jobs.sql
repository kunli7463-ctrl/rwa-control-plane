CREATE TABLE IF NOT EXISTS rwa.prover_jobs (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.zk_transaction_authorizations(transaction_id),
  tenant_id text NOT NULL,
  product_id text NOT NULL REFERENCES rwa.products(id),
  circuit_id text NOT NULL,
  circuit_version text NOT NULL,
  authorization_hash text NOT NULL CHECK (authorization_hash ~ '^[0-9a-f]{64}$'),
  witness_reference_ciphertext bytea NOT NULL,
  state text NOT NULL CHECK (state IN
    ('QUEUED','SUBMITTING','REMOTE_PENDING','VERIFYING','RETRYABLE','VERIFIED','FAILED','CANCELLED')),
  external_job_id text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts>=0 AND attempts<=32),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_owner text,
  lease_expires_at timestamptz,
  proof_receipt_id text UNIQUE REFERENCES rwa.zk_proof_receipts(id),
  last_error_code text,
  requested_by text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((lease_owner IS NULL)=(lease_expires_at IS NULL)),
  CHECK ((state='VERIFIED')=(proof_receipt_id IS NOT NULL)),
  FOREIGN KEY (circuit_id,circuit_version)
    REFERENCES rwa.proof_circuit_versions(circuit_id,circuit_version)
);

CREATE UNIQUE INDEX IF NOT EXISTS prover_jobs_remote_identity_unique
  ON rwa.prover_jobs(external_job_id) WHERE external_job_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS prover_jobs_dispatch_idx
  ON rwa.prover_jobs(state,next_attempt_at,lease_expires_at);

CREATE OR REPLACE FUNCTION rwa.guard_prover_job_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'prover jobs cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.product_id IS DISTINCT FROM OLD.product_id
     OR NEW.circuit_id IS DISTINCT FROM OLD.circuit_id
     OR NEW.circuit_version IS DISTINCT FROM OLD.circuit_version
     OR NEW.authorization_hash IS DISTINCT FROM OLD.authorization_hash
     OR NEW.witness_reference_ciphertext IS DISTINCT FROM OLD.witness_reference_ciphertext
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
     OR OLD.state IN ('VERIFIED','FAILED','CANCELLED')
     OR (OLD.state='QUEUED' AND NEW.state NOT IN ('SUBMITTING','CANCELLED'))
     OR (OLD.state='SUBMITTING' AND NEW.state NOT IN ('REMOTE_PENDING','RETRYABLE','FAILED'))
     OR (OLD.state='REMOTE_PENDING' AND NEW.state NOT IN ('VERIFYING','REMOTE_PENDING','RETRYABLE','FAILED','CANCELLED'))
     OR (OLD.state='VERIFYING' AND NEW.state NOT IN ('VERIFIED','REMOTE_PENDING','RETRYABLE','FAILED'))
     OR (OLD.state='RETRYABLE' AND NEW.state NOT IN ('SUBMITTING','VERIFYING','FAILED','CANCELLED')) THEN
    RAISE EXCEPTION 'invalid prover job lifecycle mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prover_job_lifecycle_guard ON rwa.prover_jobs;
CREATE TRIGGER prover_job_lifecycle_guard
BEFORE UPDATE OR DELETE ON rwa.prover_jobs
FOR EACH ROW EXECUTE FUNCTION rwa.guard_prover_job_lifecycle();

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('broker','transaction.zk.prover.request'),
  ('broker','transaction.zk.prover.read'),
  ('operations','transaction.zk.prover.read')
ON CONFLICT DO NOTHING;

