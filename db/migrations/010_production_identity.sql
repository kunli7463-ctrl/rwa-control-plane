CREATE TABLE IF NOT EXISTS rwa.identity_providers (
  id text PRIMARY KEY,
  issuer text NOT NULL UNIQUE,
  audience text NOT NULL,
  jwks_uri text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED')),
  required_acr text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rwa.principals (
  id text PRIMARY KEY,
  provider_id text NOT NULL REFERENCES rwa.identity_providers(id),
  subject text NOT NULL,
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
  investor_ref text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (provider_id,subject)
);

CREATE TABLE IF NOT EXISTS rwa.institution_memberships (
  principal_id text NOT NULL REFERENCES rwa.principals(id),
  tenant_id text NOT NULL,
  institution_id text REFERENCES rwa.institutions(id),
  role text NOT NULL CHECK (role IN ('issuer','distributor','investor','broker','operations','supervisor')),
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','ENDED')),
  effective_at timestamptz NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (principal_id,tenant_id,role,effective_at),
  CHECK (expires_at IS NULL OR expires_at > effective_at),
  CHECK ((role='investor') OR institution_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS active_principal_tenant_role_unique
  ON rwa.institution_memberships(principal_id,tenant_id,role)
  WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS rwa.role_permissions (
  role text NOT NULL,
  permission text NOT NULL,
  PRIMARY KEY (role,permission)
);

INSERT INTO rwa.role_permissions(role,permission) VALUES
  ('issuer','product.pause'), ('issuer','product.resume'),
  ('distributor','credential.restrict'),
  ('investor','transaction.subscribe'), ('investor','transaction.redeem'),
  ('broker','transaction.transfer'),
  ('operations','exception.propose'), ('operations','exception.approve'),
  ('operations','external_incident.propose'), ('operations','external_incident.approve'),
  ('supervisor','audit.read')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS rwa.production_sessions (
  id_hash text PRIMARY KEY CHECK (id_hash ~ '^[0-9a-f]{64}$'),
  csrf_hash text NOT NULL CHECK (csrf_hash ~ '^[0-9a-f]{64}$'),
  principal_id text NOT NULL REFERENCES rwa.principals(id),
  tenant_id text NOT NULL,
  role text NOT NULL,
  institution_id text,
  investor_ref text,
  permissions jsonb NOT NULL,
  provider_session_id text,
  auth_time timestamptz NOT NULL,
  mfa_verified_at timestamptz NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoke_reason text,
  CHECK (expires_at > issued_at),
  CHECK (jsonb_typeof(permissions)='array')
);

CREATE INDEX IF NOT EXISTS production_sessions_principal_idx
  ON rwa.production_sessions(principal_id,expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS rwa.authentication_events (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  principal_id text REFERENCES rwa.principals(id),
  tenant_id text,
  event_type text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('SUCCESS','DENIED','REVOKED')),
  reason_code text,
  provider_id text,
  provider_session_id text,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DROP TRIGGER IF EXISTS authentication_events_append_only_guard ON rwa.authentication_events;
CREATE TRIGGER authentication_events_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.authentication_events
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();

