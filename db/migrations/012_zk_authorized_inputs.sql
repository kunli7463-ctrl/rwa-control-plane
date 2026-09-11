CREATE TABLE IF NOT EXISTS rwa.zk_transaction_authorizations (
  transaction_id text PRIMARY KEY REFERENCES rwa.transaction_intents(id),
  tenant_id text NOT NULL,
  circuit_id text NOT NULL,
  circuit_version text NOT NULL,
  merkle_root numeric(78,0) NOT NULL,
  context_id numeric(78,0) NOT NULL,
  asset_type numeric(78,0) NOT NULL,
  fee numeric(78,0) NOT NULL,
  recipient numeric(78,0) NOT NULL,
  relayer numeric(78,0) NOT NULL,
  transaction_hash numeric(78,0) NOT NULL,
  input_nullifier_0 numeric(78,0) NOT NULL,
  input_nullifier_1 numeric(78,0) NOT NULL,
  output_commitment_x_0 numeric(78,0) NOT NULL,
  output_commitment_x_1 numeric(78,0) NOT NULL,
  output_commitment_y_0 numeric(78,0) NOT NULL,
  output_commitment_y_1 numeric(78,0) NOT NULL,
  public_inputs_hash text NOT NULL CHECK (public_inputs_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','VERIFIED')),
  proof_receipt_id text UNIQUE REFERENCES rwa.zk_proof_receipts(id),
  authorized_by text NOT NULL,
  authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  verified_at timestamptz,
  FOREIGN KEY (circuit_id,circuit_version)
    REFERENCES rwa.proof_circuit_versions(circuit_id,circuit_version),
  FOREIGN KEY (context_id,merkle_root)
    REFERENCES rwa.zk_merkle_roots(context_id,merkle_root),
  CHECK (input_nullifier_0 <> input_nullifier_1),
  CHECK ((status='PENDING' AND proof_receipt_id IS NULL AND verified_at IS NULL)
      OR (status='VERIFIED' AND proof_receipt_id IS NOT NULL AND verified_at IS NOT NULL))
);

CREATE OR REPLACE FUNCTION rwa.guard_zk_transaction_authorization() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ZK transaction authorizations cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.status <> 'PENDING' OR NEW.status <> 'VERIFIED'
     OR NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.circuit_id IS DISTINCT FROM OLD.circuit_id
     OR NEW.circuit_version IS DISTINCT FROM OLD.circuit_version
     OR NEW.merkle_root IS DISTINCT FROM OLD.merkle_root
     OR NEW.context_id IS DISTINCT FROM OLD.context_id
     OR NEW.asset_type IS DISTINCT FROM OLD.asset_type
     OR NEW.fee IS DISTINCT FROM OLD.fee
     OR NEW.recipient IS DISTINCT FROM OLD.recipient
     OR NEW.relayer IS DISTINCT FROM OLD.relayer
     OR NEW.transaction_hash IS DISTINCT FROM OLD.transaction_hash
     OR NEW.input_nullifier_0 IS DISTINCT FROM OLD.input_nullifier_0
     OR NEW.input_nullifier_1 IS DISTINCT FROM OLD.input_nullifier_1
     OR NEW.output_commitment_x_0 IS DISTINCT FROM OLD.output_commitment_x_0
     OR NEW.output_commitment_x_1 IS DISTINCT FROM OLD.output_commitment_x_1
     OR NEW.output_commitment_y_0 IS DISTINCT FROM OLD.output_commitment_y_0
     OR NEW.output_commitment_y_1 IS DISTINCT FROM OLD.output_commitment_y_1
     OR NEW.public_inputs_hash IS DISTINCT FROM OLD.public_inputs_hash
     OR NEW.authorized_by IS DISTINCT FROM OLD.authorized_by
     OR NEW.authorized_at IS DISTINCT FROM OLD.authorized_at THEN
    RAISE EXCEPTION 'invalid ZK authorization transition or immutable input mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_transaction_authorization_guard ON rwa.zk_transaction_authorizations;
CREATE TRIGGER zk_transaction_authorization_guard
BEFORE UPDATE OR DELETE ON rwa.zk_transaction_authorizations
FOR EACH ROW EXECUTE FUNCTION rwa.guard_zk_transaction_authorization();
