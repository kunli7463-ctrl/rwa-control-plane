import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const text = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("runtime container is non-root, production-only and health checked", async () => {
  const dockerfile = await text("../Dockerfile");
  const ignore = await text("../.dockerignore");

  assert.match(dockerfile, /npm ci --omit=dev --ignore-scripts/);
  const bases = dockerfile.split('\n').filter(line => line.startsWith('FROM '));
  assert.equal(bases.length, 2);
  for (const base of bases) assert.match(base, /^FROM node:22\.23\.2-bookworm-slim@sha256:[a-f0-9]{64} AS /);
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(dockerfile, /install -d -m 0700 -o 10001 -g 10001 \/var\/lib\/rwa-control-plane/);
  assert.match(dockerfile, /HEALTHCHECK[^\n]*\\\n\s+CMD/);
  assert.doesNotMatch(dockerfile, /COPY[^\n]*test\/fixtures/);
  assert.match(ignore, /^\.env\.\*$/m);
  assert.match(ignore, /^node_modules$/m);
  for (const excluded of ['.local-tools','circom-v2.1.6-build','release-evidence','zk-candidate']) {
    assert.ok(ignore.split('\n').includes(excluded));
  }
  assert.match(ignore, /^test\/fixtures\/groth16-local-only$/m);
});

test("PoC compose profile gates services on migration and binds only to loopback", async () => {
  const compose = await text("../deploy/compose/postgres-poc.yaml");

  assert.match(compose, /migrate:\n[\s\S]*command: \["node", "scripts\/migrate\.js"\]/);
  assert.match(compose, /web:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /outbox-worker:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /"127\.0\.0\.1:\$\{RWA_POC_WEB_PORT:-8765\}:8765"/);
  assert.match(compose, /"127\.0\.0\.1:\$\{RWA_POC_WORKER_PORT:-8770\}:8770"/);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /ZK_MODE: disabled/);
  assert.match(compose, /AUTH_MODE: sandbox/);
  assert.match(compose, /networks: \[rwa-internal, rwa-poc-frontend\]/);
  assert.match(compose, /rwa-internal:\n\s+internal: true/);
  assert.match(compose, /web:[\s\S]*NODE_ENV: development\n\s+DEPLOYMENT_PROFILE: sandbox/);
  assert.match(compose, /outbox-worker:[\s\S]*NODE_ENV: development\n\s+DEPLOYMENT_PROFILE: sandbox/);
});

test("production compose gates workloads on preflight and migration with hardened containers", async () => {
  const compose = await text("../deploy/compose/production.example.yaml");

  assert.match(compose, /image: \$\{RWA_IMAGE:\?/);
  assert.match(compose, /preflight:[\s\S]*validate-production-env\.js/);
  assert.match(compose, /artifact-check:[\s\S]*verify-groth16-artifacts\.js/);
  assert.match(compose, /migrate:[\s\S]*artifact-check:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /web:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /outbox-worker:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /prover-worker:[\s\S]*condition: service_completed_successfully/);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /cap_drop: \[ALL\]/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /127\.0\.0\.1:\$\{RWA_WEB_PORT:-8765\}:8765/);
  assert.doesNotMatch(compose, /AUTH_MODE:\s*sandbox/);
  assert.doesNotMatch(compose, /ALLOW_LOCAL_DEV_KEY:\s*["']?true/);
  // H3: migrations use a separate schema-owning env file; runtime env never carries it.
  assert.match(compose, /migrate:[\s\S]*env_file:\n\s+- \$\{RWA_MIGRATION_ENV:\?/);
  const webSection = compose.slice(compose.indexOf("\n  web:"));
  assert.doesNotMatch(webSection, /RWA_MIGRATION_ENV/);
});

test("migration identity is separate from the least-privilege runtime identity", async () => {
  const migration = await text("../deploy/migration.env.production.example");
  const runtime = await text("../deploy/container.env.production.example");
  const migrate = await text("../scripts/migrate.js");
  assert.match(migration, /^MIGRATION_DATABASE_URL=postgresql:\/\/rwa_migrator:/m);
  assert.match(migration, /^RUNTIME_DATABASE_ROLE=rwa_runtime$/m);
  assert.doesNotMatch(runtime, /^MIGRATION_DATABASE_URL=/m);
  assert.match(runtime, /^DATABASE_URL=postgresql:\/\/rwa_runtime:/m);
  assert.match(migrate, /MIGRATION_DATABASE_URL is required for production migrations/);
  assert.match(migrate, /grantRuntimePrivileges/);
});

test("production environment contract cannot silently enable local keys", async () => {
  const environment = await text("../deploy/container.env.production.example");

  assert.match(environment, /^NODE_ENV=production$/m);
  assert.match(environment, /^DEPLOYMENT_PROFILE=production$/m);
  assert.match(environment, /^TENANT_ID=REPLACE_WITH_DEPLOYMENT_TENANT$/m);
  assert.match(environment, /^AUTH_MODE=oidc$/m);
  assert.match(environment, /^COOKIE_SECURE=true$/m);
  assert.match(environment, /^ALLOW_LOCAL_DEV_KEY=false$/m);
  assert.match(environment, /^ENVELOPE_CIPHER_MODE=kms$/m);
  assert.match(environment, /^KMS_PROVIDER_MODULE=/m);
  assert.match(environment, /^ECONOMIC_COMMITMENT_KMS_KEY_ID=/m);
  assert.doesNotMatch(environment, /^ENCRYPTION_KEY_HEX=/m);
  assert.match(environment, /sslmode=verify-full/);
  assert.match(environment, /^ZK_MODE=groth16$/m);
  assert.match(environment, /^ZK_ARTIFACT_MANIFEST_SHA256=/m);
  assert.match(environment, /^OUTBOX_PUBLISHER_MODULE=/m);
});

test("production deploy runner pins the image and preserves gate order", async () => {
  const deploy = await text("../scripts/production-deploy.sh");

  assert.match(deploy, /@sha256:\[0-9a-f\]\{64\}\$/);
  assert.match(deploy, /config --quiet[\s\S]*run --rm preflight[\s\S]*run --rm artifact-check[\s\S]*run --rm migrate[\s\S]*up -d --wait/);
  assert.match(deploy, /web outbox-worker prover-worker/);
  assert.match(deploy, /PRODUCTION_DEPLOYMENT_HEALTHY/);
  assert.match(deploy, /RWA_MIGRATION_ENV must be separate from the runtime RWA_PRODUCTION_ENV/);
  assert.doesNotMatch(deploy, /down -v|rm -rf|DROP DATABASE/);
});

test("local acceptance scripts discover overridable runtimes without developer-specific paths", async () => {
  const runtime = await text("../scripts/local-runtime.sh");
  const startPostgres = await text("../scripts/start-local-postgres.sh");
  const scriptPaths = [
    "../scripts/start-local-postgres.sh",
    "../scripts/stop-local-postgres.sh",
    "../scripts/verify-local-postgres.sh",
    "../scripts/backup-local-postgres.sh",
    "../scripts/verify-local-backup-restore.sh",
  ];

  assert.match(runtime, /RWA_RUNTIME_ROOT/);
  assert.match(runtime, /RWA_NODE_BIN/);
  assert.match(runtime, /RWA_PG_PREFIX/);
  assert.match(runtime, /RWA_PG_DATA/);
  assert.match(runtime, /RWA_PG_HOST/);
  assert.match(runtime, /RWA_PG_PORT/);
  assert.match(runtime, /require_identifier/);
  assert.doesNotMatch(runtime, /\/Users\/[^/]+/);

  // psql does not expand :'name' variables inside a -c argument. Keep the
  // database existence check on the validated shell value so an existing
  // database is detected instead of being created a second time.
  assert.match(startPostgres, /require_identifier "\$PG_DATABASE"/);
  assert.match(startPostgres, /datname='\$PG_DATABASE'/);
  assert.doesNotMatch(startPostgres, /-tAc\s+"[^"]*:'database'/);

  for (const scriptPath of scriptPaths) {
    const script = await text(scriptPath);
    assert.match(script, /source "\$\{0:A:h\}\/local-runtime\.sh"/);
    assert.doesNotMatch(script, /\/Users\/[^/]+/);
  }
});
