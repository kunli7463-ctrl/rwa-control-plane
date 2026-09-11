-- M5: the parameters that decide what the confidential rail accepts (active
-- circuit artifact, product context/asset type and the genesis note tree)
-- are changed only through audited maker/checker proposals, not ad hoc SQL.
CREATE TABLE IF NOT EXISTS rwa.zk_parameter_proposals (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('CIRCUIT_ACTIVATION','PRODUCT_CONTEXT')),
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED')),
  proposed_by text NOT NULL,
  proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  decided_by text,
  decided_at timestamptz,
  decision_reason text,
  CHECK ((status='PENDING' AND decided_by IS NULL AND decided_at IS NULL AND decision_reason IS NULL)
      OR (status<>'PENDING' AND decided_by IS NOT NULL AND decided_at IS NOT NULL
          AND decision_reason IS NOT NULL AND decided_by<>proposed_by))
);

CREATE OR REPLACE FUNCTION rwa.guard_zk_parameter_proposal() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK parameter proposals cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.status<>'PENDING' OR NEW.status NOT IN ('APPROVED','REJECTED')
     OR NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
     OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by OR NEW.proposed_at IS DISTINCT FROM OLD.proposed_at THEN
    RAISE EXCEPTION 'invalid ZK parameter proposal lifecycle mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_parameter_proposal_guard ON rwa.zk_parameter_proposals;
CREATE TRIGGER zk_parameter_proposal_guard
BEFORE UPDATE OR DELETE ON rwa.zk_parameter_proposals
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_parameter_proposal();

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('operations','zk.parameters.propose'),
  ('operations','zk.parameters.approve')
ON CONFLICT DO NOTHING;
