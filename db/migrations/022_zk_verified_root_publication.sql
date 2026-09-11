-- H2: the authoritative note tree is no longer an attested opaque number.
-- Every CURRENT root carries the incremental-tree frontier that reproduces
-- it, finalization proposals are pinned to the base root they extend, and
-- a stale or mistaken proposal can be cancelled and re-proposed.

ALTER TABLE rwa.zk_merkle_roots
  ADD COLUMN IF NOT EXISTS frontier jsonb;

ALTER TABLE rwa.zk_merkle_roots
  DROP CONSTRAINT IF EXISTS zk_merkle_roots_frontier_shape_check;
ALTER TABLE rwa.zk_merkle_roots
  ADD CONSTRAINT zk_merkle_roots_frontier_shape_check
  CHECK (frontier IS NULL OR (jsonb_typeof(frontier)='array' AND jsonb_array_length(frontier)=32));

CREATE OR REPLACE FUNCTION rwa.guard_zk_merkle_root_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK Merkle roots cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF NEW.context_id IS DISTINCT FROM OLD.context_id
     OR NEW.merkle_root IS DISTINCT FROM OLD.merkle_root
     OR NEW.tree_size IS DISTINCT FROM OLD.tree_size
     OR NEW.frontier IS DISTINCT FROM OLD.frontier
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

-- A root can only become the extendable CURRENT tree if it arrives with its
-- frontier. The application recomputes the root from that frontier before
-- inserting; the database refuses frontier-less CURRENT roots outright.
CREATE OR REPLACE FUNCTION rwa.require_zk_current_root_frontier() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status='CURRENT' AND NEW.frontier IS NULL THEN
    RAISE EXCEPTION 'CURRENT ZK Merkle roots require an incremental tree frontier' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_current_root_frontier_guard ON rwa.zk_merkle_roots;
CREATE TRIGGER zk_current_root_frontier_guard
BEFORE INSERT ON rwa.zk_merkle_roots
FOR EACH ROW EXECUTE FUNCTION rwa.require_zk_current_root_frontier();

ALTER TABLE rwa.zk_finalization_proposals
  ADD COLUMN IF NOT EXISTS base_merkle_root numeric(78,0),
  ADD COLUMN IF NOT EXISTS base_tree_size bigint,
  ADD COLUMN IF NOT EXISTS cancelled_by text,
  ADD COLUMN IF NOT EXISTS cancel_reason text;

-- One live (PENDING or APPROVED) proposal per transaction; cancelled
-- proposals remain as history and no longer block a corrected proposal.
ALTER TABLE rwa.zk_finalization_proposals
  DROP CONSTRAINT IF EXISTS zk_finalization_proposals_transaction_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS zk_finalization_proposals_one_live
  ON rwa.zk_finalization_proposals(transaction_id) WHERE status IN ('PENDING','APPROVED');

ALTER TABLE rwa.zk_finalization_proposals
  DROP CONSTRAINT IF EXISTS zk_finalization_proposals_cancellation_shape_check;
ALTER TABLE rwa.zk_finalization_proposals
  ADD CONSTRAINT zk_finalization_proposals_cancellation_shape_check
  CHECK (
    (status='CANCELLED' AND cancelled_by IS NOT NULL AND cancel_reason IS NOT NULL)
    OR (status<>'CANCELLED' AND cancelled_by IS NULL AND cancel_reason IS NULL)
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
     OR NEW.base_merkle_root IS DISTINCT FROM OLD.base_merkle_root
     OR NEW.base_tree_size IS DISTINCT FROM OLD.base_tree_size
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

CREATE OR REPLACE FUNCTION rwa.require_zk_finalization_proposal_base() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.base_merkle_root IS NULL OR NEW.base_tree_size IS NULL
     OR NEW.output_tree_size <> NEW.base_tree_size + 2 THEN
    RAISE EXCEPTION 'finalization proposals must extend a pinned base tree by exactly two outputs' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_finalization_proposal_base_guard ON rwa.zk_finalization_proposals;
CREATE TRIGGER zk_finalization_proposal_base_guard
BEFORE INSERT ON rwa.zk_finalization_proposals
FOR EACH ROW EXECUTE FUNCTION rwa.require_zk_finalization_proposal_base();

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('operations','transaction.zk.finalize.cancel')
ON CONFLICT DO NOTHING;
