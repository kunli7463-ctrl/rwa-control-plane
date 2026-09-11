ALTER TABLE rwa.product_configurations
  DROP CONSTRAINT IF EXISTS product_configurations_configuration_status_check;

ALTER TABLE rwa.product_configurations
  ADD CONSTRAINT product_configurations_configuration_status_check
  CHECK (configuration_status IN
    ('DRAFT','ROLES_PENDING','READY_FOR_EVIDENCE','ACTIVATION_PENDING','ACTIVE','SUSPENDED','RETIRED'));

CREATE TABLE IF NOT EXISTS rwa.institution_onboarding_approvals (
  tenant_id text NOT NULL,
  institution_id text NOT NULL,
  approval_round integer NOT NULL CHECK (approval_round > 0),
  role text NOT NULL CHECK (role IN ('MAKER','CHECKER')),
  actor_ref text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 1000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,institution_id,approval_round,role),
  FOREIGN KEY (tenant_id,institution_id)
    REFERENCES rwa.tenant_institutions(tenant_id,institution_id)
);

CREATE OR REPLACE FUNCTION rwa.enforce_institution_onboarding_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE maker_ref text;
BEGIN
  IF NEW.role='CHECKER' THEN
    SELECT actor_ref INTO maker_ref FROM rwa.institution_onboarding_approvals
     WHERE tenant_id=NEW.tenant_id AND institution_id=NEW.institution_id
       AND approval_round=NEW.approval_round AND role='MAKER';
    IF maker_ref IS NULL THEN
      RAISE EXCEPTION 'institution checker requires maker proposal in the same round' USING ERRCODE='23514';
    END IF;
    IF maker_ref=NEW.actor_ref THEN
      RAISE EXCEPTION 'institution onboarding maker and checker must differ' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS institution_onboarding_approval_guard ON rwa.institution_onboarding_approvals;
CREATE TRIGGER institution_onboarding_approval_guard
BEFORE INSERT ON rwa.institution_onboarding_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.enforce_institution_onboarding_approval();

DROP TRIGGER IF EXISTS institution_onboarding_approvals_append_only_guard ON rwa.institution_onboarding_approvals;
CREATE TRIGGER institution_onboarding_approvals_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.institution_onboarding_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE TABLE IF NOT EXISTS rwa.product_template_evidence_requirements (
  template_id text NOT NULL REFERENCES rwa.product_templates(id),
  requirement_code text NOT NULL CHECK (requirement_code ~ '^[a-z][a-z0-9_]{2,63}$'),
  responsible_role text NOT NULL CHECK (responsible_role IN
    ('issuer','distributor','credential_issuer','fund_administrator','custodian','transfer_agent','cash_provider')),
  description text NOT NULL CHECK (char_length(description) BETWEEN 3 AND 500),
  mandatory boolean NOT NULL DEFAULT true,
  PRIMARY KEY (template_id,requirement_code)
);

INSERT INTO rwa.product_template_evidence_requirements
  (template_id,requirement_code,responsible_role,description,mandatory)
SELECT t.id, role_name || '_mandate', role_name,
       'Active mandate or agreement for required role ' || role_name, true
FROM rwa.product_templates t
CROSS JOIN LATERAL jsonb_array_elements_text(t.required_roles) AS role_name
ON CONFLICT DO NOTHING;

INSERT INTO rwa.product_template_evidence_requirements
  (template_id,requirement_code,responsible_role,description,mandatory)
SELECT id,'offering_document','issuer','Approved offering or product disclosure document',true
FROM rwa.product_templates
ON CONFLICT DO NOTHING;

INSERT INTO rwa.product_template_evidence_requirements
  (template_id,requirement_code,responsible_role,description,mandatory)
SELECT id,'legal_opinion','issuer','Jurisdiction-specific legal and regulatory opinion',true
FROM rwa.product_templates
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS rwa.product_evidence_requirements (
  product_id text NOT NULL REFERENCES rwa.products(id),
  requirement_code text NOT NULL,
  responsible_role text NOT NULL,
  description text NOT NULL,
  mandatory boolean NOT NULL,
  status text NOT NULL DEFAULT 'MISSING' CHECK (status IN ('MISSING','SATISFIED','REJECTED')),
  evidence_id text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (product_id,requirement_code)
);

CREATE TABLE IF NOT EXISTS rwa.product_activation_evidence (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{2,99}$'),
  product_id text NOT NULL,
  requirement_code text NOT NULL,
  source_institution_id text NOT NULL REFERENCES rwa.institutions(id),
  schema_version text NOT NULL CHECK (char_length(schema_version) BETWEEN 1 AND 40),
  content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL CHECK (char_length(signature) BETWEEN 16 AND 16384),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  received_by text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (product_id,requirement_code)
    REFERENCES rwa.product_evidence_requirements(product_id,requirement_code),
  CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS product_activation_evidence_current_idx
  ON rwa.product_activation_evidence(product_id,requirement_code,expires_at DESC);

ALTER TABLE rwa.product_evidence_requirements
  DROP CONSTRAINT IF EXISTS product_evidence_requirements_evidence_id_fkey;
ALTER TABLE rwa.product_evidence_requirements
  ADD CONSTRAINT product_evidence_requirements_evidence_id_fkey
  FOREIGN KEY (evidence_id) REFERENCES rwa.product_activation_evidence(id);

DROP TRIGGER IF EXISTS product_activation_evidence_append_only_guard ON rwa.product_activation_evidence;
CREATE TRIGGER product_activation_evidence_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.product_activation_evidence
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE TABLE IF NOT EXISTS rwa.product_activation_approvals (
  product_id text NOT NULL REFERENCES rwa.products(id),
  approval_round integer NOT NULL CHECK (approval_round > 0),
  role text NOT NULL CHECK (role IN ('MAKER','CHECKER')),
  actor_ref text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ACTIVATE','APPROVE','REJECT')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 1000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (product_id,approval_round,role),
  CHECK ((role='MAKER' AND decision='ACTIVATE') OR (role='CHECKER' AND decision IN ('APPROVE','REJECT')))
);

CREATE OR REPLACE FUNCTION rwa.enforce_product_activation_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE maker_ref text;
BEGIN
  IF NEW.role='CHECKER' THEN
    SELECT actor_ref INTO maker_ref FROM rwa.product_activation_approvals
     WHERE product_id=NEW.product_id AND approval_round=NEW.approval_round AND role='MAKER';
    IF maker_ref IS NULL THEN
      RAISE EXCEPTION 'activation checker requires maker proposal in the same round' USING ERRCODE='23514';
    END IF;
    IF maker_ref=NEW.actor_ref THEN
      RAISE EXCEPTION 'product activation maker and checker must differ' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS product_activation_approval_guard ON rwa.product_activation_approvals;
CREATE TRIGGER product_activation_approval_guard
BEFORE INSERT ON rwa.product_activation_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.enforce_product_activation_approval();

DROP TRIGGER IF EXISTS product_activation_approvals_append_only_guard ON rwa.product_activation_approvals;
CREATE TRIGGER product_activation_approvals_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.product_activation_approvals
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

CREATE TABLE IF NOT EXISTS rwa.product_configuration_snapshots (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES rwa.platform_tenants(id),
  product_id text NOT NULL REFERENCES rwa.products(id),
  configuration_version bigint NOT NULL CHECK (configuration_version > 0),
  event_type text NOT NULL,
  actor_ref text NOT NULL,
  snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
  snapshot_hash text NOT NULL CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (product_id,configuration_version)
);

DROP TRIGGER IF EXISTS product_configuration_snapshots_append_only_guard ON rwa.product_configuration_snapshots;
CREATE TRIGGER product_configuration_snapshots_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.product_configuration_snapshots
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

INSERT INTO rwa.product_evidence_requirements
  (product_id,requirement_code,responsible_role,description,mandatory)
SELECT c.product_id,r.requirement_code,r.responsible_role,r.description,r.mandatory
FROM rwa.product_configurations c
JOIN rwa.product_template_evidence_requirements r ON r.template_id=c.template_id
ON CONFLICT DO NOTHING;

UPDATE rwa.product_configurations c
SET configuration_status='ACTIVE',updated_at=clock_timestamp()
FROM rwa.products p
WHERE p.id=c.product_id AND p.status='ACTIVE';

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('operations','institution.review.propose'),
  ('operations','institution.review.approve'),
  ('operations','product.evidence.attach'),
  ('operations','product.activation.propose'),
  ('operations','product.activation.approve'),
  ('operations','catalog.audit.read'),
  ('supervisor','catalog.audit.read')
ON CONFLICT DO NOTHING;
