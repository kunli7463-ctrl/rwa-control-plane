import assert from "node:assert/strict";
import test from "node:test";
import {
  validateOutboxWorkerDeployment,
  validateProductionDeployment,
} from "../src/production-preflight.js";

function validEnvironment() {
  return {
    NODE_ENV: "production",
    DEPLOYMENT_PROFILE: "production",
    TENANT_ID: "my-regulated-tenant",
    STORAGE_MODE: "postgres",
    DATABASE_URL: "postgresql://rwa_runtime:secret@db.internal:5432/rwa?sslmode=verify-full",
    AUTH_MODE: "oidc",
    PUBLIC_ORIGIN: "https://rwa.test",
    COOKIE_SECURE: "true",
    ENVELOPE_CIPHER_MODE: "kms",
    KMS_PROVIDER_MODULE: "/run/rwa/providers/kms-provider.js",
    KMS_KEY_ID: "alias/rwa-envelope-v1",
    ECONOMIC_COMMITMENT_KMS_KEY_ID: "alias/rwa-economic-v1",
    ALLOW_LOCAL_DEV_KEY: "false",
    ZK_MODE: "groth16",
    ZK_ARTIFACT_DIR: "/run/rwa/zk-artifacts",
    ZK_ARTIFACT_MANIFEST_SHA256: "ab".repeat(32),
    PROVER_MODE: "isolated",
    PROVER_ENDPOINT: "https://prover.internal.test/v1",
    PROVER_SERVICE_TOKEN: "s".repeat(64),
    PROVER_EXPECTED_SERVICE_ID: "prover-my-1",
    PROVER_TENANT_ID: "my-regulated-tenant",
    OUTBOX_TENANT_ID: "my-regulated-tenant",
    OUTBOX_PUBLISHER_MODULE: "/run/rwa/providers/outbox-publisher.js",
  };
}

test("production preflight accepts a complete tenant-scoped external-provider contract", () => {
  const result = validateProductionDeployment(validEnvironment(), { cwd: "/opt/rwa" });
  assert.equal(result.tenantId, "my-regulated-tenant");
  assert.equal(result.databaseHost, "db.internal");
  assert.equal(result.zkMode, "groth16");
  assert.equal(result.proverMode, "isolated");
});

test("production preflight rejects placeholders, reserved endpoints and loopback databases", () => {
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), PROVER_SERVICE_TOKEN: "REPLACE_WITH_SECRET_MANAGER_VALUE",
  }), { code: "PRODUCTION_PLACEHOLDER_FORBIDDEN" });
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), PUBLIC_ORIGIN: "https://rwa.example.com",
  }), { code: "PRODUCTION_RESERVED_ENDPOINT_FORBIDDEN" });
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), DATABASE_URL: "postgresql://rwa:secret@127.0.0.1/rwa?sslmode=verify-full",
  }), { code: "PRODUCTION_DATABASE_ENDPOINT_INVALID" });
});

test("production preflight rejects relative providers and cross-tenant workers", () => {
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), OUTBOX_PUBLISHER_MODULE: "providers/outbox.js",
  }), { code: "PRODUCTION_ABSOLUTE_PATH_REQUIRED" });
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), PROVER_TENANT_ID: "another-tenant",
  }), { code: "PRODUCTION_TENANT_SCOPE_MISMATCH" });
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(), OUTBOX_TENANT_ID: "another-tenant",
  }), { code: "PRODUCTION_TENANT_SCOPE_MISMATCH" });
});

test("production Outbox cannot fall back to sandbox or cross a tenant boundary", () => {
  assert.throws(() => validateOutboxWorkerDeployment({ NODE_ENV: "production" }), {
    code: "PRODUCTION_PROFILE_REQUIRED",
  });
  assert.throws(() => validateOutboxWorkerDeployment({
    NODE_ENV: "production", DEPLOYMENT_PROFILE: "production",
    TENANT_ID: "tenant-a", OUTBOX_TENANT_ID: "tenant-b",
    OUTBOX_PUBLISHER_MODULE: "/run/rwa/providers/outbox.js",
  }), { code: "PRODUCTION_TENANT_SCOPE_MISMATCH" });
  assert.deepEqual(validateOutboxWorkerDeployment({
    NODE_ENV: "production", DEPLOYMENT_PROFILE: "production",
    TENANT_ID: "tenant-a", OUTBOX_TENANT_ID: "tenant-a",
    OUTBOX_PUBLISHER_MODULE: "/run/rwa/providers/outbox.js",
  }), { deploymentProfile: "production", tenantId: "tenant-a" });
});

test("runtime environment cannot carry schema-owning migration credentials", () => {
  assert.throws(() => validateProductionDeployment({
    ...validEnvironment(),
    MIGRATION_DATABASE_URL: "postgresql://rwa_migrator:secret@db.internal:5432/rwa?sslmode=verify-full",
  }), { code: "MIGRATION_CREDENTIAL_IN_RUNTIME_ENV" });
});
