import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";

function configError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const DEPLOYMENT_PLACEHOLDER = /(REPLACE_(?:ME|WITH_[A-Z0-9_]+)|CHANGE_ME|CHANGEME|YOUR_[A-Z0-9_]+)/i;

export function loadRuntimeConfig(env = process.env, { cwd = process.cwd() } = {}) {
  const deploymentProfile = env.DEPLOYMENT_PROFILE ?? "sandbox";
  if (!new Set(["sandbox", "production"]).has(deploymentProfile)) {
    throw configError("INVALID_DEPLOYMENT_PROFILE", "DEPLOYMENT_PROFILE must be sandbox or production");
  }
  const nodeEnvironment = env.NODE_ENV ?? "development";
  if (nodeEnvironment === "production" && deploymentProfile !== "production") {
    throw configError(
      "PRODUCTION_PROFILE_REQUIRED",
      "NODE_ENV=production requires DEPLOYMENT_PROFILE=production",
    );
  }
  const storageMode = env.STORAGE_MODE ?? "memory";
  if (!new Set(["memory", "postgres"]).has(storageMode)) {
    throw configError("INVALID_STORAGE_MODE", "STORAGE_MODE must be memory or postgres");
  }
  const config = {
    deploymentProfile,
    nodeEnvironment,
    tenantId: env.TENANT_ID ?? "sandbox-hk",
    defaultProductId: env.DEFAULT_PRODUCT_ID ?? null,
    storageMode,
    databaseUrl: env.DATABASE_URL ?? null,
    authMode: env.AUTH_MODE ?? "sandbox",
    publicOrigin: env.PUBLIC_ORIGIN ?? null,
    cookieSecure: env.COOKIE_SECURE === "true",
    encryptionKeyHex: env.ENCRYPTION_KEY_HEX ?? null,
    encryptionKeyId: env.ENCRYPTION_KEY_ID ?? "local-dev-v1",
    envelopeCipherMode: env.ENVELOPE_CIPHER_MODE ?? "local",
    kmsProviderModule: env.KMS_PROVIDER_MODULE ? resolve(cwd, env.KMS_PROVIDER_MODULE) : null,
    kmsKeyId: env.KMS_KEY_ID ?? null,
    economicCommitmentKmsKeyId: env.ECONOMIC_COMMITMENT_KMS_KEY_ID ?? null,
    allowLocalDevelopmentKey: env.ALLOW_LOCAL_DEV_KEY === "true",
    localKeyFile: resolve(cwd, env.LOCAL_KEY_FILE ?? ".local/dev-encryption-key.json"),
    zkMode: env.ZK_MODE ?? "disabled",
    zkArtifactDirectory: env.ZK_ARTIFACT_DIR ? resolve(cwd, env.ZK_ARTIFACT_DIR) : null,
    zkManifestSha256: env.ZK_ARTIFACT_MANIFEST_SHA256 ?? null,
    proverMode: env.PROVER_MODE ?? "disabled",
    proverEndpoint: env.PROVER_ENDPOINT ?? null,
    proverServiceToken: env.PROVER_SERVICE_TOKEN ?? null,
    proverExpectedServiceId: env.PROVER_EXPECTED_SERVICE_ID ?? null,
  };
  if (!new Set(["sandbox", "oidc"]).has(config.authMode)) {
    throw configError("INVALID_AUTH_MODE", "AUTH_MODE must be sandbox or oidc");
  }
  if (!new Set(["local", "kms"]).has(config.envelopeCipherMode)) {
    throw configError("INVALID_ENVELOPE_CIPHER_MODE", "ENVELOPE_CIPHER_MODE must be local or kms");
  }
  if (config.authMode === "oidc" && storageMode !== "postgres") {
    throw configError("PRODUCTION_AUTH_REQUIRES_POSTGRES", "OIDC authentication requires PostgreSQL session storage");
  }
  if (config.authMode === "oidc" && !config.cookieSecure) {
    throw configError("SECURE_COOKIE_REQUIRED", "OIDC authentication requires COOKIE_SECURE=true");
  }
  if (config.authMode === "oidc") {
    let origin;
    try { origin = new URL(config.publicOrigin); } catch { /* checked below */ }
    if (!origin || origin.protocol !== "https:" || origin.origin !== config.publicOrigin) {
      throw configError("PUBLIC_ORIGIN_REQUIRED", "OIDC authentication requires an exact HTTPS PUBLIC_ORIGIN");
    }
    if (config.databaseUrl) {
      let database;
      try { database = new URL(config.databaseUrl); } catch { /* checked below */ }
      if (!database || !new Set(["postgres:", "postgresql:"]).has(database.protocol)
          || database.searchParams.get("sslmode") !== "verify-full") {
        throw configError("DATABASE_TLS_REQUIRED", "OIDC production mode requires PostgreSQL sslmode=verify-full");
      }
    }
  }
  if (storageMode === "postgres" && !config.databaseUrl) {
    throw configError("DATABASE_URL_REQUIRED", "PostgreSQL storage mode requires DATABASE_URL");
  }
  if (!new Set(["disabled", "groth16"]).has(config.zkMode)) {
    throw configError("INVALID_ZK_MODE", "ZK_MODE must be disabled or groth16");
  }
  if (config.zkMode === "groth16" && storageMode !== "postgres") {
    throw configError("GROTH16_REQUIRES_POSTGRES", "Groth16 proof state requires PostgreSQL storage");
  }
  if (config.zkMode === "groth16" && !config.zkArtifactDirectory) {
    throw configError("ZK_ARTIFACT_DIR_REQUIRED", "Groth16 mode requires ZK_ARTIFACT_DIR");
  }
  if (config.zkMode === "groth16" && !/^[0-9a-f]{64}$/.test(config.zkManifestSha256 ?? "")) {
    throw configError("ZK_MANIFEST_HASH_REQUIRED", "Groth16 mode requires a lowercase manifest SHA-256 pin");
  }
  if (!new Set(["disabled", "isolated"]).has(config.proverMode)) {
    throw configError("INVALID_PROVER_MODE", "PROVER_MODE must be disabled or isolated");
  }
  if (config.proverMode === "isolated") {
    if (config.zkMode !== "groth16" || storageMode !== "postgres") {
      throw configError("ISOLATED_PROVER_REQUIRES_GROTH16", "isolated prover mode requires PostgreSQL and Groth16 verification");
    }
    let endpoint;
    try { endpoint = new URL(config.proverEndpoint); } catch { /* checked below */ }
    if (!endpoint || endpoint.protocol !== "https:" || endpoint.username || endpoint.password
        || endpoint.search || endpoint.hash) {
      throw configError("PROVER_ENDPOINT_REQUIRED", "isolated prover mode requires an HTTPS prover endpoint without embedded credentials");
    }
    if (typeof config.proverServiceToken !== "string" || config.proverServiceToken.length < 32) {
      throw configError("PROVER_CREDENTIAL_REQUIRED", "isolated prover mode requires a service credential");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(config.proverExpectedServiceId ?? "")) {
      throw configError("PROVER_IDENTITY_REQUIRED", "isolated prover mode requires a pinned service identity");
    }
  }
  if (storageMode === "postgres" && config.envelopeCipherMode === "local"
      && !config.encryptionKeyHex && !config.allowLocalDevelopmentKey) {
    throw configError(
      "ENCRYPTION_KEY_REQUIRED",
      "PostgreSQL storage mode requires ENCRYPTION_KEY_HEX or explicit ALLOW_LOCAL_DEV_KEY=true",
    );
  }
  if (config.encryptionKeyHex && !/^[0-9a-fA-F]{64}$/.test(config.encryptionKeyHex)) {
    throw configError("INVALID_ENCRYPTION_KEY", "ENCRYPTION_KEY_HEX must contain exactly 32 bytes");
  }
  if (config.envelopeCipherMode === "kms") {
    if (!config.kmsProviderModule) {
      throw configError("KMS_PROVIDER_REQUIRED", "KMS envelope mode requires KMS_PROVIDER_MODULE");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/.test(config.kmsKeyId ?? "")) {
      throw configError("KMS_KEY_ID_REQUIRED", "KMS envelope mode requires a valid KMS_KEY_ID");
    }
  }
  if (deploymentProfile === "production") {
    if (nodeEnvironment !== "production") {
      throw configError("PRODUCTION_NODE_ENV_REQUIRED", "production profile requires NODE_ENV=production");
    }
    if (storageMode !== "postgres" || config.authMode !== "oidc") {
      throw configError("PRODUCTION_DURABILITY_REQUIRED", "production profile requires PostgreSQL and OIDC");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(config.tenantId)
        || config.tenantId === "sandbox-hk") {
      throw configError("PRODUCTION_TENANT_REQUIRED", "production profile requires an explicit non-sandbox TENANT_ID");
    }
    if (config.envelopeCipherMode !== "kms") {
      throw configError("PRODUCTION_KMS_REQUIRED", "production profile requires KMS envelope encryption");
    }
    if (config.encryptionKeyHex || config.allowLocalDevelopmentKey) {
      throw configError(
        "LOCAL_KEY_FORBIDDEN_IN_PRODUCTION",
        "production profile forbids raw and local development encryption keys",
      );
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/.test(config.economicCommitmentKmsKeyId ?? "")) {
      throw configError(
        "ECONOMIC_COMMITMENT_KMS_KEY_REQUIRED",
        "production profile requires ECONOMIC_COMMITMENT_KMS_KEY_ID",
      );
    }
    const productionValues = [
      config.tenantId, config.databaseUrl, config.publicOrigin, config.kmsProviderModule,
      config.kmsKeyId, config.economicCommitmentKmsKeyId, config.zkArtifactDirectory,
      config.zkManifestSha256, config.proverEndpoint, config.proverServiceToken,
      config.proverExpectedServiceId,
    ].filter((value) => value != null);
    if (productionValues.some((value) => DEPLOYMENT_PLACEHOLDER.test(String(value)))) {
      throw configError(
        "PRODUCTION_PLACEHOLDER_FORBIDDEN",
        "production runtime configuration cannot contain deployment placeholders",
      );
    }
  }
  return config;
}

export async function resolveEncryptionKey(config) {
  if (config.envelopeCipherMode !== "local") {
    throw configError("LOCAL_KEY_MODE_REQUIRED", "raw encryption key resolution is limited to local envelope mode");
  }
  if (config.encryptionKeyHex) return Buffer.from(config.encryptionKeyHex, "hex");
  if (!config.allowLocalDevelopmentKey) throw configError("ENCRYPTION_KEY_REQUIRED", "encryption key is unavailable");

  try {
    const saved = JSON.parse(await readFile(config.localKeyFile, "utf8"));
    if (saved.keyId !== config.encryptionKeyId || !/^[0-9a-f]{64}$/.test(saved.keyHex ?? "")) {
      throw configError("INVALID_LOCAL_KEY_FILE", "local development key file is invalid or has a different key id");
    }
    return Buffer.from(saved.keyHex, "hex");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  await mkdir(dirname(config.localKeyFile), { recursive: true, mode: 0o700 });
  const keyHex = randomBytes(32).toString("hex");
  try {
    await writeFile(
      config.localKeyFile,
      `${JSON.stringify({ keyId: config.encryptionKeyId, keyHex })}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    return Buffer.from(keyHex, "hex");
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const saved = JSON.parse(await readFile(config.localKeyFile, "utf8"));
    if (saved.keyId !== config.encryptionKeyId || !/^[0-9a-f]{64}$/.test(saved.keyHex ?? "")) {
      throw configError("INVALID_LOCAL_KEY_FILE", "local development key file is invalid after concurrent creation");
    }
    return Buffer.from(saved.keyHex, "hex");
  }
}

export async function loadKmsProvider(config, { importer = (specifier) => import(specifier) } = {}) {
  if (config.envelopeCipherMode !== "kms") {
    throw configError("KMS_MODE_REQUIRED", "KMS provider loading requires ENVELOPE_CIPHER_MODE=kms");
  }
  let providerModule;
  try {
    providerModule = await importer(config.kmsProviderModule);
  } catch (cause) {
    throw configError("KMS_PROVIDER_LOAD_FAILED", `KMS provider could not be loaded: ${cause.message}`);
  }
  const factory = providerModule.createKmsProvider ?? providerModule.default;
  if (typeof factory !== "function") {
    throw configError("INVALID_KMS_PROVIDER_MODULE", "KMS provider module must export createKmsProvider");
  }
  let provider;
  try {
    provider = await factory({ keyId: config.kmsKeyId, deploymentProfile: config.deploymentProfile });
  } catch (cause) {
    throw configError("KMS_PROVIDER_INITIALIZATION_FAILED", `KMS provider initialization failed: ${cause.message}`);
  }
  if (!provider || typeof provider.wrapDataKey !== "function" || typeof provider.unwrapDataKey !== "function") {
    throw configError("INVALID_KMS_PROVIDER", "KMS provider must implement wrapDataKey and unwrapDataKey");
  }
  if (config.deploymentProfile === "production" && typeof provider.generateMac !== "function") {
    throw configError(
      "KMS_MAC_PROVIDER_REQUIRED",
      "production KMS provider must implement generateMac for economic commitments",
    );
  }
  return provider;
}
