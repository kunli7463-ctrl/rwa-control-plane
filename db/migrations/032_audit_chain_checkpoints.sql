-- L3: the audit hash chain is segmented per aggregate, so removing an entire
-- aggregate leaves no trace inside the chain. Checkpoints fold every audit
-- event, in global sequence order, into a rolling digest. A checkpoint digest
-- is the value to publish to an external anchor (notary, timestamping service,
-- counterparty): once published, any later deletion or edit of an event below
-- that point fails recomputation.

CREATE TABLE IF NOT EXISTS rwa.audit_chain_checkpoints (
  tenant_id text NOT NULL,
  checkpoint_number bigint NOT NULL CHECK (checkpoint_number > 0),
  through_sequence_id bigint NOT NULL CHECK (through_sequence_id > 0),
  event_count bigint NOT NULL CHECK (event_count >= 0),
  previous_digest text CHECK (previous_digest ~ '^[0-9a-f]{64}$'),
  digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  external_anchor jsonb,
  PRIMARY KEY (tenant_id, checkpoint_number)
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_chain_checkpoints_through_idx
  ON rwa.audit_chain_checkpoints(tenant_id, through_sequence_id);

-- Checkpoints are append-only, except for recording where a digest was anchored.
CREATE OR REPLACE FUNCTION rwa.guard_audit_chain_checkpoint() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'audit chain checkpoints cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.external_anchor IS NOT NULL
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.checkpoint_number IS DISTINCT FROM OLD.checkpoint_number
     OR NEW.through_sequence_id IS DISTINCT FROM OLD.through_sequence_id
     OR NEW.event_count IS DISTINCT FROM OLD.event_count
     OR NEW.previous_digest IS DISTINCT FROM OLD.previous_digest
     OR NEW.digest IS DISTINCT FROM OLD.digest
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.external_anchor IS NULL THEN
    RAISE EXCEPTION 'audit chain checkpoints are append-only; only a missing external anchor may be recorded'
      USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS audit_chain_checkpoint_guard ON rwa.audit_chain_checkpoints;
CREATE TRIGGER audit_chain_checkpoint_guard
BEFORE UPDATE OR DELETE ON rwa.audit_chain_checkpoints
FOR EACH ROW EXECUTE FUNCTION rwa.guard_audit_chain_checkpoint();
