-- H4: remote status polls are not failure attempts. `attempts` now counts
-- failed or abandoned attempts only (bounded by the service retry policy),
-- while `poll_count` records how often a remote job was checked.
ALTER TABLE rwa.prover_jobs
  ADD COLUMN IF NOT EXISTS poll_count integer NOT NULL DEFAULT 0 CHECK (poll_count >= 0);

CREATE INDEX IF NOT EXISTS prover_jobs_expired_lease_idx
  ON rwa.prover_jobs(tenant_id,lease_expires_at)
  WHERE state IN ('SUBMITTING','VERIFYING');
