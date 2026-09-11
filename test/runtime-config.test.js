import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadKmsProvider, loadRuntimeConfig, resolveEncryptionKey } from "../src/runtime-config.js";
import { DemoRuntime } from "../src/demo-runtime.js";

test("runtime configuration rejects ambiguous or incomplete PostgreSQL mode", () => {
  assert.throws(() => loadRuntimeConfig({ STORAGE_MODE: "invalid" }), { code: "INVALID_STORAGE_MODE" });
  assert.throws(() => loadRuntimeConfig({ STORAGE_MODE: "postgres" }), { code: "DATABASE_URL_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({
    STORAGE_MODE: "postgres",
    DATABASE_URL: "postgres://localhost/test",
  }), { code: "ENCRYPTION_KEY_REQUIRED" });
});

test("Groth16 runtime configuration pins PostgreSQL and the artifact manifest", () => {
  assert.throws(() => loadRuntimeConfig({ ZK_MODE: "unknown" }), { code: "INVALID_ZK_MODE" });
  assert.throws(() => loadRuntimeConfig({ ZK_MODE: "groth16" }), { code: "GROTH16_REQUIRES_POSTGRES" });
  const base = {
    ZK_MODE: "groth16", STORAGE_MODE: "postgres", DATABASE_URL: "postgres://localhost/test",
    ENCRYPTION_KEY_HEX: "11".repeat(32),
  };
  assert.throws(() => loadRuntimeConfig(base), { code: "ZK_ARTIFACT_DIR_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({ ...base, ZK_ARTIFACT_DIR: "artifacts" }), {
    code: "ZK_MANIFEST_HASH_REQUIRED",
  });
  const config = loadRuntimeConfig({
    ...base, ZK_ARTIFACT_DIR: "artifacts", ZK_ARTIFACT_MANIFEST_SHA256: "ab".repeat(32),
  }, { cwd: "/tmp/rwa" });
  assert.equal(config.zkMode, "groth16");
  assert.equal(config.zkArtifactDirectory, "/tmp/rwa/artifacts");
});

test("explicit hexadecimal encryption key is validated", async () => {
  const keyHex = "ab".repeat(32);
  const config = loadRuntimeConfig({
    STORAGE_MODE: "postgres",
    DATABASE_URL: "postgres://localhost/test",
    ENCRYPTION_KEY_HEX: keyHex,
  });
  assert.deepEqual(await resolveEncryptionKey(config), Buffer.from(keyHex, "hex"));
  assert.throws(() => loadRuntimeConfig({
    STORAGE_MODE: "postgres",
    DATABASE_URL: "postgres://localhost/test",
    ENCRYPTION_KEY_HEX: "abcd",
  }), { code: "INVALID_ENCRYPTION_KEY" });
});

test("isolated prover configuration fails closed without Groth16 and pinned HTTPS identity", () => {
  assert.throws(() => loadRuntimeConfig({ PROVER_MODE: "unknown" }), { code: "INVALID_PROVER_MODE" });
  assert.throws(() => loadRuntimeConfig({ PROVER_MODE: "isolated" }), {
    code: "ISOLATED_PROVER_REQUIRES_GROTH16",
  });
  const base = {
    STORAGE_MODE: "postgres", DATABASE_URL: "postgres://localhost/test", ENCRYPTION_KEY_HEX: "11".repeat(32),
    ZK_MODE: "groth16", ZK_ARTIFACT_DIR: "artifacts", ZK_ARTIFACT_MANIFEST_SHA256: "ab".repeat(32),
    PROVER_MODE: "isolated", PROVER_SERVICE_TOKEN: "t".repeat(64), PROVER_EXPECTED_SERVICE_ID: "prover-hk-1",
  };
  assert.throws(() => loadRuntimeConfig({ ...base, PROVER_ENDPOINT: "http://prover.test" }), {
    code: "PROVER_ENDPOINT_REQUIRED",
  });
  const config = loadRuntimeConfig({ ...base, PROVER_ENDPOINT: "https://prover.test/v1" });
  assert.equal(config.proverMode, "isolated");
  assert.equal(config.proverExpectedServiceId, "prover-hk-1");
});

test("explicitly enabled local development key is persistent and permission-restricted", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rwa-key-test-"));
  try {
    const config = loadRuntimeConfig({
      STORAGE_MODE: "postgres",
      DATABASE_URL: "postgres://localhost/test",
      ALLOW_LOCAL_DEV_KEY: "true",
      LOCAL_KEY_FILE: "keys/dev.json",
    }, { cwd: directory });
    const first = await resolveEncryptionKey(config);
    const second = await resolveEncryptionKey(config);
    assert.equal(first.length, 32);
    assert.deepEqual(second, first);
    const saved = JSON.parse(await readFile(config.localKeyFile, "utf8"));
    assert.equal(saved.keyId, "local-dev-v1");
    assert.equal((await stat(config.localKeyFile)).mode & 0o777, 0o600);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("production identity mode fails closed without PostgreSQL and secure cookies", () => {
  assert.throws(() => loadRuntimeConfig({ AUTH_MODE: "oidc" }), {
    code: "PRODUCTION_AUTH_REQUIRES_POSTGRES",
  });
  assert.throws(() => loadRuntimeConfig({
    AUTH_MODE: "oidc", STORAGE_MODE: "postgres", DATABASE_URL: "postgres://local",
    ENCRYPTION_KEY_HEX: "11".repeat(32),
  }), { code: "SECURE_COOKIE_REQUIRED" });
  assert.equal(loadRuntimeConfig({
    AUTH_MODE: "oidc", STORAGE_MODE: "postgres", DATABASE_URL: "postgres://local/db?sslmode=verify-full",
    ENCRYPTION_KEY_HEX: "11".repeat(32), COOKIE_SECURE: "true", PUBLIC_ORIGIN: "https://rwa.example",
  }).authMode, "oidc");
  assert.throws(() => loadRuntimeConfig({
    AUTH_MODE: "oidc", STORAGE_MODE: "postgres", DATABASE_URL: "postgres://local/db?sslmode=require",
    ENCRYPTION_KEY_HEX: "11".repeat(32), COOKIE_SECURE: "true", PUBLIC_ORIGIN: "https://rwa.example",
  }), { code: "DATABASE_TLS_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({
    AUTH_MODE: "oidc", STORAGE_MODE: "postgres", DATABASE_URL: "postgres://local",
    ENCRYPTION_KEY_HEX: "11".repeat(32), COOKIE_SECURE: "true", PUBLIC_ORIGIN: "http://rwa.example",
  }), { code: "PUBLIC_ORIGIN_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({ AUTH_MODE: "unknown" }), { code: "INVALID_AUTH_MODE" });
});

test("NODE_ENV production cannot silently select sandbox defaults", () => {
  assert.throws(() => loadRuntimeConfig({ NODE_ENV: "production" }), {
    code: "PRODUCTION_PROFILE_REQUIRED",
  });
  assert.throws(() => loadRuntimeConfig({ DEPLOYMENT_PROFILE: "unknown" }), {
    code: "INVALID_DEPLOYMENT_PROFILE",
  });
});

test("production profile requires a non-sandbox tenant, KMS, PostgreSQL and OIDC", () => {
  assert.throws(() => loadRuntimeConfig({
    DEPLOYMENT_PROFILE: "production", NODE_ENV: "development",
  }), { code: "PRODUCTION_NODE_ENV_REQUIRED" });

  const identityBase = {
    DEPLOYMENT_PROFILE: "production", NODE_ENV: "production",
    STORAGE_MODE: "postgres", DATABASE_URL: "postgresql://db/rwa?sslmode=verify-full",
    AUTH_MODE: "oidc", COOKIE_SECURE: "true", PUBLIC_ORIGIN: "https://rwa.example",
  };
  assert.throws(() => loadRuntimeConfig({
    ...identityBase, ENCRYPTION_KEY_HEX: "11".repeat(32),
  }), { code: "PRODUCTION_TENANT_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({
    ...identityBase, TENANT_ID: "institution-a", ENCRYPTION_KEY_HEX: "11".repeat(32),
  }), { code: "PRODUCTION_KMS_REQUIRED" });
  assert.throws(() => loadRuntimeConfig({
    ...identityBase, TENANT_ID: "institution-a", ENVELOPE_CIPHER_MODE: "kms",
    KMS_PROVIDER_MODULE: "kms-provider.js", KMS_KEY_ID: "key-v1", ENCRYPTION_KEY_HEX: "11".repeat(32),
  }), { code: "LOCAL_KEY_FORBIDDEN_IN_PRODUCTION" });

  const config = loadRuntimeConfig({
    ...identityBase, TENANT_ID: "institution-a", ENVELOPE_CIPHER_MODE: "kms",
    KMS_PROVIDER_MODULE: "kms-provider.js", KMS_KEY_ID: "key-v1",
    ECONOMIC_COMMITMENT_KMS_KEY_ID: "mac-key-v1",
  }, { cwd: "/opt/rwa" });
  assert.equal(config.deploymentProfile, "production");
  assert.equal(config.kmsProviderModule, "/opt/rwa/kms-provider.js");
  assert.throws(() => loadRuntimeConfig({
    ...identityBase, TENANT_ID: "REPLACE_WITH_DEPLOYMENT_TENANT", ENVELOPE_CIPHER_MODE: "kms",
    KMS_PROVIDER_MODULE: "kms-provider.js", KMS_KEY_ID: "key-v1",
    ECONOMIC_COMMITMENT_KMS_KEY_ID: "mac-key-v1",
  }), { code: "PRODUCTION_PLACEHOLDER_FORBIDDEN" });
});

test("KMS provider loader validates module, initialization and provider interface", async () => {
  const config = loadRuntimeConfig({
    STORAGE_MODE: "postgres", DATABASE_URL: "postgres://localhost/test",
    ENVELOPE_CIPHER_MODE: "kms", KMS_PROVIDER_MODULE: "kms-provider.js", KMS_KEY_ID: "key-v1",
  }, { cwd: "/opt/rwa" });
  const provider = await loadKmsProvider(config, {
    importer: async () => ({
      createKmsProvider: async ({ keyId }) => ({
        keyId, wrapDataKey() {}, unwrapDataKey() {},
      }),
    }),
  });
  assert.equal(provider.keyId, "key-v1");
  await assert.rejects(loadKmsProvider(config, { importer: async () => ({}) }), {
    code: "INVALID_KMS_PROVIDER_MODULE",
  });
  await assert.rejects(loadKmsProvider(config, {
    importer: async () => ({ createKmsProvider: async () => ({}) }),
  }), { code: "INVALID_KMS_PROVIDER" });
});

test("sandbox runtime rejects non-sandbox tenants before any database work", async () => {
  await assert.rejects(DemoRuntime.create({
    deploymentProfile: "sandbox", tenantId: "institution-a",
  }), { code: "DEMO_RUNTIME_FORBIDDEN" });
});

test("sandbox identity switching refuses non-loopback listeners unless explicitly container-bound", () => {
  assert.throws(() => loadRuntimeConfig({ HOST: "0.0.0.0" }), { code: "SANDBOX_REMOTE_BIND_FORBIDDEN" });
  assert.throws(() => loadRuntimeConfig({ HOST: "10.0.0.5", AUTH_MODE: "sandbox" }), { code: "SANDBOX_REMOTE_BIND_FORBIDDEN" });
  assert.equal(loadRuntimeConfig({}).host, "127.0.0.1");
  assert.equal(loadRuntimeConfig({ HOST: "::1" }).host, "::1");
  assert.equal(loadRuntimeConfig({ HOST: "0.0.0.0", SANDBOX_CONTAINER_BIND: "true" }).host, "0.0.0.0");
});
