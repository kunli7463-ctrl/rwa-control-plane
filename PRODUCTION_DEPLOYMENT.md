# Production deployment contract

This repository supplies application components and fail-closed configuration
checks. It does not supply or impersonate the regulated institution, OIDC
directory, KMS/HSM, managed PostgreSQL, external settlement adapter or trusted
Groth16 ceremony.

## Mandatory sequence

1. Copy `deploy/container.env.production.example` outside the repository and
   replace every placeholder through the deployment secret/config platform.
2. Mount reviewed KMS and Outbox provider modules read-only under
   `/run/rwa/providers` and the independently approved Groth16 bundle under
   `/run/rwa/zk-artifacts`.
3. Pin `RWA_IMAGE` by digest, never by a mutable tag.
4. Run the configuration preflight and pinned-artifact check containers. A
   non-zero exit from either blocks migration and rollout.
5. Run migrations as a one-shot identity with schema-change privileges. Copy
   `deploy/migration.env.production.example` to a separate secret file
   (`RWA_MIGRATION_ENV`). `MIGRATION_DATABASE_URL` owns schema `rwa`;
   `RUNTIME_DATABASE_ROLE` receives only `SELECT, INSERT, UPDATE` on tables and
   `USAGE, SELECT` on sequences — no `DELETE`, `TRUNCATE`, `TRIGGER` or DDL.
   The runtime env must not contain `MIGRATION_DATABASE_URL` (preflight fails),
   and Web, Outbox and prover workers refuse to start
   (`DATABASE_RUNTIME_ROLE_TOO_PRIVILEGED`) if their database identity is a
   superuser, owns or can create objects in `rwa`, or holds destructive grants —
   otherwise it could disable the append-only triggers that protect spent
   nullifiers and the audit chain.
6. Start Web, Outbox and prover workers using separate workload identities.
7. Put an authenticated TLS reverse proxy/WAF in front of the loopback-bound
   Web port. Worker health endpoints are not externally published.

```sh
export RWA_IMAGE='registry.example/rwa-control-plane@sha256:REPLACE_WITH_DIGEST'
export RWA_PRODUCTION_ENV='/secure/config/rwa-production.env'
export RWA_MIGRATION_ENV='/secure/config/rwa-migration.env'
export RWA_PROVIDER_DIR='/secure/providers'
export RWA_ZK_ARTIFACT_DIR='/secure/zk-artifacts'

docker compose -f deploy/compose/production.example.yaml config
docker compose -f deploy/compose/production.example.yaml run --rm preflight
docker compose -f deploy/compose/production.example.yaml run --rm artifact-check
docker compose -f deploy/compose/production.example.yaml run --rm migrate
docker compose -f deploy/compose/production.example.yaml up -d web outbox-worker prover-worker
```

The same ordered gate is available as one guarded command:

```sh
./scripts/production-deploy.sh
```

It refuses mutable image tags and missing or relative mount paths, validates
the rendered Compose model, then runs configuration preflight, artifact check,
migration and health-gated workload startup in that order. It does not perform
database rollback. Schema rollback must be designed per migration and approved
with the institution before a production change.

Passing preflight proves only that the configuration contract is internally
consistent. It does not certify the external providers, jurisdictional setup,
infrastructure controls or cryptographic ceremony.

## OIDC login exchange

The browser-facing login is bound to a server-issued, single-use challenge:

1. `POST /api/oidc/login-challenge` (same `Origin` as `PUBLIC_ORIGIN`) returns
   `{ nonce, expiresAt }` and sets the HttpOnly `rwa_oidc_nonce` cookie scoped
   to `/api/oidc` for five minutes.
2. The front end starts the identity provider's authorization-code flow with
   that `nonce` and obtains the ID token.
3. `POST /api/oidc/session` with `{ idToken, tenantId, role }`. The token's
   `nonce` claim must match the cookie, the challenge is consumed, and the
   token hash is recorded so the same ID token can never be exchanged twice
   (`OIDC_TOKEN_REPLAYED`). Tokens with several audiences, or any `azp`, must
   name this client as `azp`. JWKS retrieval happens before a database
   transaction is opened.

Both endpoints and `/api/institution-callbacks` are rate limited per client
address inside each instance (`AUTH_RATE_LIMIT_PER_MINUTE`, default 60;
`CALLBACK_RATE_LIMIT_PER_MINUTE`, default 600). Behind a reverse proxy all
clients may share one address, so size these limits for the proxy and keep
global rate limiting at the edge.
