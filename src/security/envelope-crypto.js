import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function cryptoError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

export class LocalKeyring {
  constructor({ activeKeyId, keys }) {
    this.activeKeyId = activeKeyId;
    this.keys = new Map(Object.entries(keys ?? {}).map(([keyId, key]) => {
      const material = Buffer.isBuffer(key) ? Buffer.from(key) : Buffer.from(key, "hex");
      if (material.length !== 32) throw cryptoError("INVALID_MASTER_KEY", `key ${keyId} must contain 32 bytes`);
      return [keyId, material];
    }));
    if (!this.keys.has(activeKeyId)) throw cryptoError("UNKNOWN_ACTIVE_KEY", "active encryption key is unavailable");
  }

  active() {
    return { keyId: this.activeKeyId, key: this.get(this.activeKeyId) };
  }

  get(keyId) {
    const key = this.keys.get(keyId);
    if (!key) throw cryptoError("UNKNOWN_ENCRYPTION_KEY", `encryption key ${keyId} is unavailable`);
    return key;
  }
}

export class AesGcmEnvelopeCipher {
  constructor(keyring) {
    this.keyring = keyring;
    this.mode = "AES_256_GCM";
  }

  encrypt(value, context) {
    const { keyId, key } = this.keyring.active();
    const iv = randomBytes(12);
    const aad = Buffer.from(canonicalize({ schema: "rwa-private-v1", ...context }));
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(canonicalize(value), "utf8"), cipher.final()]);
    const envelope = {
      v: 1,
      alg: "A256GCM",
      kid: keyId,
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    return Buffer.from(JSON.stringify(envelope));
  }

  decrypt(encodedEnvelope, context) {
    let envelope;
    try {
      envelope = JSON.parse(Buffer.from(encodedEnvelope).toString("utf8"));
    } catch (cause) {
      throw cryptoError("INVALID_CIPHERTEXT_ENVELOPE", "private payload envelope is malformed", cause);
    }
    if (envelope.v !== 1 || envelope.alg !== "A256GCM" || typeof envelope.kid !== "string") {
      throw cryptoError("UNSUPPORTED_CIPHERTEXT_ENVELOPE", "private payload envelope version is unsupported");
    }
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.keyring.get(envelope.kid), Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(Buffer.from(canonicalize({ schema: "rwa-private-v1", ...context })));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
      return JSON.parse(plaintext.toString("utf8"));
    } catch (cause) {
      if (cause.code === "UNKNOWN_ENCRYPTION_KEY") throw cause;
      throw cryptoError("CIPHERTEXT_AUTHENTICATION_FAILED", "private payload authentication failed", cause);
    }
  }
}

export class KmsEnvelopeCipher {
  constructor(provider) {
    if (!provider || typeof provider.wrapDataKey !== "function" || typeof provider.unwrapDataKey !== "function") {
      throw cryptoError("INVALID_KMS_PROVIDER", "KMS provider must wrap and unwrap data keys");
    }
    this.provider = provider;
    this.mode = "KMS_ENVELOPE_AES_256_GCM";
  }

  async encrypt(value, context) {
    const dataKey = randomBytes(32);
    const iv = randomBytes(12);
    const aad = Buffer.from(canonicalize({ schema: "rwa-private-v2", ...context }));
    try {
      const cipher = createCipheriv("aes-256-gcm", dataKey, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(canonicalize(value), "utf8"), cipher.final()]);
      const wrapped = await this.provider.wrapDataKey(dataKey, { schema: "rwa-private-v2", ...context });
      if (!wrapped?.keyId || !Buffer.isBuffer(wrapped.wrappedKey)) {
        throw cryptoError("INVALID_KMS_RESPONSE", "KMS provider returned an invalid wrapped data key");
      }
      return Buffer.from(JSON.stringify({
        v: 2, alg: "A256GCM", keyManagement: "KMS_ENVELOPE", kid: wrapped.keyId,
        edk: wrapped.wrappedKey.toString("base64"), iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64"),
      }));
    } finally {
      dataKey.fill(0);
    }
  }

  async decrypt(encodedEnvelope, context) {
    let envelope;
    try { envelope = JSON.parse(Buffer.from(encodedEnvelope).toString("utf8")); }
    catch (cause) { throw cryptoError("INVALID_CIPHERTEXT_ENVELOPE", "private payload envelope is malformed", cause); }
    if (envelope.v !== 2 || envelope.alg !== "A256GCM" || envelope.keyManagement !== "KMS_ENVELOPE"
        || typeof envelope.kid !== "string" || typeof envelope.edk !== "string") {
      throw cryptoError("UNSUPPORTED_CIPHERTEXT_ENVELOPE", "KMS envelope version is unsupported");
    }
    const kmsContext = { schema: "rwa-private-v2", ...context };
    let dataKey;
    try {
      dataKey = await this.provider.unwrapDataKey({
        keyId: envelope.kid, wrappedKey: Buffer.from(envelope.edk, "base64"), context: kmsContext,
      });
      if (!Buffer.isBuffer(dataKey) || dataKey.length !== 32) {
        throw cryptoError("INVALID_KMS_RESPONSE", "KMS provider returned an invalid data key");
      }
      const decipher = createDecipheriv("aes-256-gcm", dataKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(Buffer.from(canonicalize(kmsContext)));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final(),
      ]);
      return JSON.parse(plaintext.toString("utf8"));
    } catch (cause) {
      if (cause.code?.startsWith("KMS_") || cause.code === "INVALID_KMS_RESPONSE") throw cause;
      throw cryptoError("CIPHERTEXT_AUTHENTICATION_FAILED", "private payload authentication failed", cause);
    } finally {
      dataKey?.fill(0);
    }
  }
}

export class SoftwareKmsProvider {
  constructor({ activeKeyId, keys }) {
    this.activeKeyId = activeKeyId;
    this.keys = new Map(Object.entries(keys ?? {}).map(([keyId, key]) => [keyId, {
      material: Buffer.from(key), enabled: true,
    }]));
    for (const [keyId, entry] of this.keys) {
      if (entry.material.length !== 32) throw cryptoError("INVALID_MASTER_KEY", `KMS key ${keyId} must contain 32 bytes`);
    }
    if (!this.keys.has(activeKeyId)) throw cryptoError("KMS_KEY_UNAVAILABLE", "active KMS key is unavailable");
  }

  disable(keyId) {
    const entry = this.keys.get(keyId);
    if (!entry) throw cryptoError("KMS_KEY_UNAVAILABLE", "KMS key is unavailable");
    entry.enabled = false;
  }

  setActive(keyId) {
    this.#key(keyId);
    this.activeKeyId = keyId;
  }

  async wrapDataKey(dataKey, context) {
    const entry = this.#key(this.activeKeyId);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", entry.material, iv);
    cipher.setAAD(Buffer.from(canonicalize({ domain: "rwa-kms-wrap-v1", ...context })));
    const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
    return { keyId: this.activeKeyId, wrappedKey: Buffer.concat([iv, cipher.getAuthTag(), ciphertext]) };
  }

  async unwrapDataKey({ keyId, wrappedKey, context }) {
    const entry = this.#key(keyId);
    try {
      const decipher = createDecipheriv("aes-256-gcm", entry.material, wrappedKey.subarray(0, 12));
      decipher.setAAD(Buffer.from(canonicalize({ domain: "rwa-kms-wrap-v1", ...context })));
      decipher.setAuthTag(wrappedKey.subarray(12, 28));
      return Buffer.concat([decipher.update(wrappedKey.subarray(28)), decipher.final()]);
    } catch (cause) {
      throw cryptoError("KMS_UNWRAP_FAILED", "wrapped data key could not be unwrapped", cause);
    }
  }

  #key(keyId) {
    const entry = this.keys.get(keyId);
    if (!entry?.enabled) throw cryptoError("KMS_KEY_UNAVAILABLE", `KMS key ${keyId} is unavailable or disabled`);
    return entry;
  }
}

export class RedactedPayloadCipher {
  constructor() {
    this.mode = "REDACTED_NO_RECOVERY";
  }

  encrypt() {
    return Buffer.from("SANDBOX_REDACTED");
  }

  decrypt() {
    throw cryptoError("PRIVATE_PAYLOAD_UNAVAILABLE", "private payload was intentionally redacted");
  }
}
