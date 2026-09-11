CREATE TABLE IF NOT EXISTS rwa.institution_signing_keys (
  institution_id text NOT NULL REFERENCES rwa.institutions(id),
  key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  algorithm text NOT NULL CHECK (algorithm IN ('Ed25519')),
  public_key_pem text NOT NULL CHECK (char_length(public_key_pem) BETWEEN 64 AND 16384),
  status text NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (institution_id,key_id),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  CHECK ((status='REVOKED' AND revoked_at IS NOT NULL) OR (status<>'REVOKED' AND revoked_at IS NULL))
);

CREATE INDEX IF NOT EXISTS institution_signing_keys_active_idx
  ON rwa.institution_signing_keys(institution_id,status,valid_from,valid_until);

CREATE OR REPLACE FUNCTION rwa.guard_institution_signing_key_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'institution signing keys cannot be deleted' USING ERRCODE='23514';
  END IF;
  IF NEW.institution_id<>OLD.institution_id OR NEW.key_id<>OLD.key_id
     OR NEW.algorithm<>OLD.algorithm OR NEW.public_key_pem<>OLD.public_key_pem
     OR NEW.valid_from<>OLD.valid_from OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'institution signing key identity and material are immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.status<>'ACTIVE' AND NEW.status<>OLD.status THEN
    RAISE EXCEPTION 'retired or revoked institution signing keys cannot be reactivated' USING ERRCODE='23514';
  END IF;
  IF OLD.valid_until IS NOT NULL AND (NEW.valid_until IS NULL OR NEW.valid_until>OLD.valid_until) THEN
    RAISE EXCEPTION 'institution signing key validity cannot be extended after restriction' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS institution_signing_key_lifecycle_guard ON rwa.institution_signing_keys;
CREATE TRIGGER institution_signing_key_lifecycle_guard
BEFORE UPDATE OR DELETE ON rwa.institution_signing_keys
FOR EACH ROW EXECUTE FUNCTION rwa.guard_institution_signing_key_lifecycle();

INSERT INTO rwa.institution_signing_keys
  (institution_id,key_id,algorithm,public_key_pem,status,valid_from)
SELECT id,'primary-v1','Ed25519',public_key_pem,'ACTIVE',created_at
FROM rwa.institutions
WHERE char_length(public_key_pem) BETWEEN 64 AND 16384
  AND position('BEGIN PUBLIC KEY' IN public_key_pem) > 0
ON CONFLICT (institution_id,key_id) DO NOTHING;

CREATE OR REPLACE FUNCTION rwa.register_primary_institution_signing_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF char_length(NEW.public_key_pem) BETWEEN 64 AND 16384
     AND position('BEGIN PUBLIC KEY' IN NEW.public_key_pem) > 0 THEN
    INSERT INTO rwa.institution_signing_keys
      (institution_id,key_id,algorithm,public_key_pem,status,valid_from)
    VALUES (NEW.id,'primary-v1','Ed25519',NEW.public_key_pem,'ACTIVE',NEW.created_at)
    ON CONFLICT (institution_id,key_id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS institution_primary_signing_key_guard ON rwa.institutions;
CREATE TRIGGER institution_primary_signing_key_guard
AFTER INSERT ON rwa.institutions
FOR EACH ROW EXECUTE FUNCTION rwa.register_primary_institution_signing_key();

ALTER TABLE rwa.product_activation_evidence
  ADD COLUMN IF NOT EXISTS envelope_version text,
  ADD COLUMN IF NOT EXISTS signature_algorithm text,
  ADD COLUMN IF NOT EXISTS signing_key_id text,
  ADD COLUMN IF NOT EXISTS canonical_payload_hash text,
  ADD COLUMN IF NOT EXISTS verification_status text NOT NULL DEFAULT 'UNVERIFIED',
  ADD COLUMN IF NOT EXISTS verifier_version text,
  ADD COLUMN IF NOT EXISTS verified_at timestamptz;

ALTER TABLE rwa.product_activation_evidence
  DROP CONSTRAINT IF EXISTS product_activation_evidence_verification_status_check;
ALTER TABLE rwa.product_activation_evidence
  ADD CONSTRAINT product_activation_evidence_verification_status_check
  CHECK (verification_status IN ('UNVERIFIED','VERIFIED'));

ALTER TABLE rwa.product_activation_evidence
  DROP CONSTRAINT IF EXISTS product_activation_evidence_verified_shape_check;
ALTER TABLE rwa.product_activation_evidence
  ADD CONSTRAINT product_activation_evidence_verified_shape_check
  CHECK (
    verification_status <> 'VERIFIED'
    OR (
      envelope_version='rwa.product-activation-evidence.v1'
      AND signature_algorithm='Ed25519'
      AND signing_key_id IS NOT NULL
      AND canonical_payload_hash ~ '^[0-9a-f]{64}$'
      AND verifier_version IS NOT NULL
      AND verified_at IS NOT NULL
    )
  );

ALTER TABLE rwa.product_activation_evidence
  DROP CONSTRAINT IF EXISTS product_activation_evidence_signing_key_fkey;
ALTER TABLE rwa.product_activation_evidence
  ADD CONSTRAINT product_activation_evidence_signing_key_fkey
  FOREIGN KEY (source_institution_id,signing_key_id)
  REFERENCES rwa.institution_signing_keys(institution_id,key_id);

CREATE OR REPLACE FUNCTION rwa.invalidate_evidence_for_signing_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status='ACTIVE' AND NEW.status IN ('RETIRED','REVOKED') THEN
    UPDATE rwa.product_evidence_requirements r
       SET status='MISSING',evidence_id=NULL,updated_at=clock_timestamp()
      FROM rwa.product_activation_evidence e
     WHERE r.evidence_id=e.id
       AND e.source_institution_id=NEW.institution_id
       AND e.signing_key_id=NEW.key_id;

    UPDATE rwa.product_configurations c
       SET configuration_status='SUSPENDED',configuration_version=configuration_version+1,
           updated_at=clock_timestamp()
     WHERE c.configuration_status='ACTIVE'
       AND EXISTS (
         SELECT 1 FROM rwa.product_evidence_requirements r
          WHERE r.product_id=c.product_id AND r.mandatory AND r.status<>'SATISFIED'
       );

    UPDATE rwa.products p
       SET status='PAUSED',row_version=row_version+1,updated_at=clock_timestamp()
     WHERE p.status='ACTIVE'
       AND EXISTS (
         SELECT 1 FROM rwa.product_configurations c
          WHERE c.product_id=p.id AND c.configuration_status='SUSPENDED'
       );
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS institution_signing_key_invalidation_guard ON rwa.institution_signing_keys;
CREATE TRIGGER institution_signing_key_invalidation_guard
AFTER UPDATE OF status ON rwa.institution_signing_keys
FOR EACH ROW EXECUTE FUNCTION rwa.invalidate_evidence_for_signing_key();

-- Evidence accepted before this migration was never cryptographically verified.
-- Fail closed: retain the append-only rows for audit, but do not let them satisfy
-- an activation requirement or keep an active product enabled.
UPDATE rwa.product_evidence_requirements r
SET status='MISSING',evidence_id=NULL,updated_at=clock_timestamp()
WHERE r.evidence_id IN (
  SELECT e.id FROM rwa.product_activation_evidence e
  WHERE e.verification_status<>'VERIFIED'
);

UPDATE rwa.product_configurations c
SET configuration_status='SUSPENDED',configuration_version=configuration_version+1,
    updated_at=clock_timestamp()
WHERE c.configuration_status='ACTIVE'
  AND EXISTS (
    SELECT 1 FROM rwa.product_evidence_requirements r
    WHERE r.product_id=c.product_id AND r.mandatory AND r.status<>'SATISFIED'
  );

UPDATE rwa.products p
SET status='PAUSED',row_version=row_version+1,updated_at=clock_timestamp()
WHERE p.status='ACTIVE'
  AND EXISTS (
    SELECT 1 FROM rwa.product_configurations c
    WHERE c.product_id=p.id AND c.configuration_status='SUSPENDED'
  );

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('issuer','institution.key.manage')
ON CONFLICT DO NOTHING;
