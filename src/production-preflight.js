import { isAbsolute, resolve } from "node:path";
import { loadRuntimeConfig } from "./runtime-config.js";

function preflightError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const PLACEHOLDER = /(REPLACE_(?:ME|WITH_[A-Z0-9_]+)|CHANGE_ME|CHANGEME|YOUR_[A-Z0-9_]+)/i;

function required(env, name) {
  const value = env[name];
  if (typeof value !== "string" || value.trim() === "") {
    throw preflightError("PRODUCTION_VALUE_REQUIRED", `${name} is required`);
  }
  if (PLACEHOLDER.test(value)) {
    throw preflightError("PRODUCTION_PLACEHOLDER_FORBIDDEN", `${name} still contains a deployment placeholder`);
  }
  return value;
}

function absolutePath(env, name, cwd) {
  const value = required(env, name);
  if (!isAbsolute(value)) {
    throw preflightError("PRODUCTION_ABSOLUTE_PATH_REQUIRED", `${name} must be an absolute mounted path`);
  }
  return resolve(cwd, value);
}

function requireSameTenant(env, name, tenantId) {
  const value = required(env, name);
  if (value !== tenantId) {
    throw preflightError("PRODUCTION_TENANT_SCOPE_MISMATCH", `${name} must exactly match TENANT_ID`);
  }
}

export function validateProductionDeployment(env, { cwd = process.cwd() } = {}) {
  const config = loadRuntimeConfig(env, { cwd });
  if (config.deploymentProfile !== "production") {
    throw preflightError("PRODUCTION_PROFILE_REQUIRED", "deployment preflight accepts only DEPLOYMENT_PROFILE=production");
  }
  if (config.zkMode !== "groth16" || config.proverMode !== "isolated") {
    throw preflightError(
      "PRODUCTION_CONFIDENTIAL_RUNTIME_REQUIRED",
      "full production deployment requires ZK_MODE=groth16 and PROVER_MODE=isolated",
    );
  }

  const critical = [
    "TENANT_ID", "DATABASE_URL", "PUBLIC_ORIGIN", "KMS_KEY_ID",
    "ECONOMIC_COMMITMENT_KMS_KEY_ID", "ZK_ARTIFACT_MANIFEST_SHA256",
    "PROVER_ENDPOINT", "PROVER_SERVICE_TOKEN", "PROVER_EXPECTED_SERVICE_ID",
    "OUTBOX_PUBLISHER_MODULE",
  ];
  for (const name of critical) required(env, name);
  if (env.MIGRATION_DATABASE_URL) {
    throw preflightError(
      "MIGRATION_CREDENTIAL_IN_RUNTIME_ENV",
      "MIGRATION_DATABASE_URL belongs only in the one-shot migration environment, never in the runtime environment",
    );
  }

  absolutePath(env, "KMS_PROVIDER_MODULE", cwd);
  absolutePath(env, "ZK_ARTIFACT_DIR", cwd);
  absolutePath(env, "OUTBOX_PUBLISHER_MODULE", cwd);
  requireSameTenant(env, "PROVER_TENANT_ID", config.tenantId);
  requireSameTenant(env, "OUTBOX_TENANT_ID", config.tenantId);

  const database = new URL(config.databaseUrl);
  if (!database.username || !database.hostname || database.hostname === "localhost" || database.hostname === "127.0.0.1") {
    throw preflightError(
      "PRODUCTION_DATABASE_ENDPOINT_INVALID",
      "DATABASE_URL requires a named user and a non-loopback database host",
    );
  }
  const origin = new URL(config.publicOrigin);
  if (origin.hostname.endsWith(".example") || origin.hostname.endsWith(".example.com")) {
    throw preflightError("PRODUCTION_RESERVED_ENDPOINT_FORBIDDEN", "PUBLIC_ORIGIN cannot use a reserved example domain");
  }
  const prover = new URL(config.proverEndpoint);
  if (prover.hostname.endsWith(".example") || prover.hostname.endsWith(".example.com")) {
    throw preflightError("PRODUCTION_RESERVED_ENDPOINT_FORBIDDEN", "PROVER_ENDPOINT cannot use a reserved example domain");
  }

  return Object.freeze({
    deploymentProfile: config.deploymentProfile,
    tenantId: config.tenantId,
    storageMode: config.storageMode,
    authMode: config.authMode,
    envelopeCipherMode: config.envelopeCipherMode,
    zkMode: config.zkMode,
    proverMode: config.proverMode,
    publicOrigin: config.publicOrigin,
    databaseHost: database.hostname,
    kmsProviderModule: config.kmsProviderModule,
    zkArtifactDirectory: config.zkArtifactDirectory,
    outboxPublisherModule: resolve(cwd, env.OUTBOX_PUBLISHER_MODULE),
  });
}

export function validateOutboxWorkerDeployment(env, { cwd = process.cwd() } = {}) {
  const deploymentProfile = env.DEPLOYMENT_PROFILE ?? "sandbox";
  const nodeEnvironment = env.NODE_ENV ?? "development";
  if (nodeEnvironment === "production" && deploymentProfile !== "production") {
    throw preflightError(
      "PRODUCTION_PROFILE_REQUIRED",
      "NODE_ENV=production Outbox worker requires DEPLOYMENT_PROFILE=production",
    );
  }
  if (!new Set(["sandbox", "production"]).has(deploymentProfile)) {
    throw preflightError("INVALID_DEPLOYMENT_PROFILE", "Outbox deployment profile must be sandbox or production");
  }
  const tenantId = env.OUTBOX_TENANT_ID ?? env.TENANT_ID ?? "sandbox-hk";
  if (deploymentProfile === "production") {
    if (tenantId === "sandbox-hk" || PLACEHOLDER.test(tenantId)) {
      throw preflightError("PRODUCTION_TENANT_REQUIRED", "production Outbox requires a non-placeholder tenant");
    }
    if (env.TENANT_ID && tenantId !== env.TENANT_ID) {
      throw preflightError("PRODUCTION_TENANT_SCOPE_MISMATCH", "OUTBOX_TENANT_ID must exactly match TENANT_ID");
    }
    absolutePath(env, "OUTBOX_PUBLISHER_MODULE", cwd);
  }
  return Object.freeze({ deploymentProfile, tenantId });
}
