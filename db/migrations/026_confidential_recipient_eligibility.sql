-- H1 (server side): a confidential transfer names its sender and recipient
-- investors and their product credentials. The public `recipient` field must
-- be a note owner key registered to an eligible recipient investor. With the
-- v3 circuit, that key is also the owner of the value-carrying output.

CREATE TABLE IF NOT EXISTS rwa.confidential_note_owner_keys (
  product_id text NOT NULL REFERENCES rwa.products(id),
  owner_public_key numeric(78,0) NOT NULL
    CHECK (owner_public_key>0 AND owner_public_key<21888242871839275222246405745257275088548364400416034343698204186575808495617),
  subject_ref text NOT NULL,
  credential_id text NOT NULL REFERENCES rwa.credentials(id),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  registered_by text NOT NULL,
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_by text,
  revoked_at timestamptz,
  revoke_reason text,
  PRIMARY KEY (product_id,owner_public_key),
  CHECK ((status='ACTIVE' AND revoked_by IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
      OR (status='REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS confidential_note_owner_keys_subject_idx
  ON rwa.confidential_note_owner_keys(product_id,subject_ref,status);

CREATE OR REPLACE FUNCTION rwa.guard_confidential_note_owner_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'confidential note owner keys cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF OLD.status<>'ACTIVE' OR NEW.status<>'REVOKED'
     OR NEW.product_id IS DISTINCT FROM OLD.product_id
     OR NEW.owner_public_key IS DISTINCT FROM OLD.owner_public_key
     OR NEW.subject_ref IS DISTINCT FROM OLD.subject_ref
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.registered_by IS DISTINCT FROM OLD.registered_by
     OR NEW.registered_at IS DISTINCT FROM OLD.registered_at THEN
    RAISE EXCEPTION 'invalid confidential note owner key mutation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS confidential_note_owner_key_guard ON rwa.confidential_note_owner_keys;
CREATE TRIGGER confidential_note_owner_key_guard
BEFORE UPDATE OR DELETE ON rwa.confidential_note_owner_keys
FOR EACH ROW EXECUTE FUNCTION rwa.guard_confidential_note_owner_key();

ALTER TABLE rwa.zk_execution_instructions
  ADD COLUMN IF NOT EXISTS sender_subject_ref text,
  ADD COLUMN IF NOT EXISTS sender_credential_id text REFERENCES rwa.credentials(id),
  ADD COLUMN IF NOT EXISTS recipient_subject_ref text,
  ADD COLUMN IF NOT EXISTS recipient_credential_id text REFERENCES rwa.credentials(id);

-- New execution instructions must identify both parties. Rows written before
-- this migration stay readable but can no longer be authorized or accepted.
CREATE OR REPLACE FUNCTION rwa.require_zk_instruction_parties() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.sender_subject_ref IS NULL OR NEW.sender_credential_id IS NULL
     OR NEW.recipient_subject_ref IS NULL OR NEW.recipient_credential_id IS NULL THEN
    RAISE EXCEPTION 'confidential execution instructions must name eligible sender and recipient credentials'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zk_instruction_parties_guard ON rwa.zk_execution_instructions;
CREATE TRIGGER zk_instruction_parties_guard
BEFORE INSERT ON rwa.zk_execution_instructions
FOR EACH ROW EXECUTE FUNCTION rwa.require_zk_instruction_parties();

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('distributor','confidential.owner_key.register'),
  ('distributor','confidential.owner_key.revoke')
ON CONFLICT DO NOTHING;
