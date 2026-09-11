-- M3: an ID token is accepted only once and only by the browser session that
-- started the login. The server issues a single-use nonce (stored as a hash,
-- delivered in an HttpOnly cookie); the token's `nonce` claim must match it,
-- and every accepted token is recorded so it cannot be replayed.
CREATE TABLE IF NOT EXISTS rwa.oidc_login_challenges (
  nonce_hash text PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX IF NOT EXISTS oidc_login_challenges_expiry_idx ON rwa.oidc_login_challenges(expires_at);

CREATE OR REPLACE FUNCTION rwa.guard_oidc_login_challenge() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'OIDC login challenges cannot be deleted by the runtime' USING ERRCODE='55000';
  END IF;
  IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
     OR NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'OIDC login challenges are single use' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS oidc_login_challenge_guard ON rwa.oidc_login_challenges;
CREATE TRIGGER oidc_login_challenge_guard
BEFORE UPDATE OR DELETE ON rwa.oidc_login_challenges
FOR EACH ROW EXECUTE FUNCTION rwa.guard_oidc_login_challenge();

CREATE TABLE IF NOT EXISTS rwa.oidc_consumed_tokens (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  provider_id text NOT NULL REFERENCES rwa.identity_providers(id),
  subject text NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS oidc_consumed_tokens_expiry_idx ON rwa.oidc_consumed_tokens(expires_at);

DROP TRIGGER IF EXISTS oidc_consumed_tokens_append_only_guard ON rwa.oidc_consumed_tokens;
CREATE TRIGGER oidc_consumed_tokens_append_only_guard
BEFORE UPDATE OR DELETE ON rwa.oidc_consumed_tokens
FOR EACH ROW EXECUTE FUNCTION rwa.reject_append_only_mutation();
