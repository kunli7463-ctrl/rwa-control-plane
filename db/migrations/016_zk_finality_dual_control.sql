CREATE TABLE IF NOT EXISTS rwa.zk_finalization_proposals (
  id text PRIMARY KEY,
  transaction_id text NOT NULL UNIQUE REFERENCES rwa.zk_settlements(transaction_id),
  tenant_id text NOT NULL,
  output_merkle_root numeric(78,0) NOT NULL,
  output_tree_size bigint NOT NULL CHECK (output_tree_size>=2),
  root_source_reference text NOT NULL,
  execution_reference text NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','APPROVED','CANCELLED')),
  proposed_by text NOT NULL,
  proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  approved_by text,
  approved_at timestamptz,
  CHECK (
    (status='PENDING' AND approved_by IS NULL AND approved_at IS NULL) OR
    (status='APPROVED' AND approved_by IS NOT NULL AND approved_at IS NOT NULL
      AND approved_by<>proposed_by) OR
    (status='CANCELLED' AND approved_by IS NULL AND approved_at IS NOT NULL)
  )
);

CREATE OR REPLACE FUNCTION rwa.guard_zk_finalization_proposal_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK finalization proposals cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.status<>'PENDING' OR NEW.status NOT IN ('APPROVED','CANCELLED')
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.output_merkle_root IS DISTINCT FROM OLD.output_merkle_root
     OR NEW.output_tree_size IS DISTINCT FROM OLD.output_tree_size
     OR NEW.root_source_reference IS DISTINCT FROM OLD.root_source_reference
     OR NEW.execution_reference IS DISTINCT FROM OLD.execution_reference
     OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by
     OR NEW.proposed_at IS DISTINCT FROM OLD.proposed_at
     OR NEW.approved_at IS NULL
     OR (NEW.status='APPROVED' AND (NEW.approved_by IS NULL OR NEW.approved_by=OLD.proposed_by))
     OR (NEW.status='CANCELLED' AND NEW.approved_by IS NOT NULL) THEN
    RAISE EXCEPTION 'invalid ZK finalization proposal lifecycle mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_finalization_proposal_lifecycle_guard ON rwa.zk_finalization_proposals;
CREATE TRIGGER zk_finalization_proposal_lifecycle_guard
BEFORE UPDATE OR DELETE ON rwa.zk_finalization_proposals
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_finalization_proposal_lifecycle();

ALTER TABLE rwa.zk_root_publication_attestations
  ADD COLUMN IF NOT EXISTS proposal_id text REFERENCES rwa.zk_finalization_proposals(id),
  ADD COLUMN IF NOT EXISTS approved_by text;

ALTER TABLE rwa.zk_root_publication_attestations DISABLE TRIGGER zk_root_publication_attestations_append_only_guard;
UPDATE rwa.zk_root_publication_attestations
SET approved_by=attested_by
WHERE approved_by IS NULL;
ALTER TABLE rwa.zk_root_publication_attestations ENABLE TRIGGER zk_root_publication_attestations_append_only_guard;

ALTER TABLE rwa.zk_root_publication_attestations
  ALTER COLUMN approved_by SET NOT NULL;

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('operations','transaction.zk.finalize.propose'),
  ('operations','transaction.zk.finalize.approve')
ON CONFLICT DO NOTHING;
