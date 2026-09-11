import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function deriveEconomicCommitmentKey(masterKey) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length < 32) throw new TypeError("master key must contain at least 32 bytes");
  return Buffer.from(hkdfSync("sha256", masterKey, Buffer.from("rwa-control-plane"), Buffer.from("economic-commitment-v1"), 32));
}

export class EconomicCommitter {
  constructor({ key = null, keyId, keys = null }) {
    if (!keyId) throw new TypeError("economic commitment key id is required");
    this.keys = new Map(Object.entries(keys ?? {}));
    if (key) this.keys.set(keyId, key);
    this.keys = new Map([...this.keys].map(([id, material]) => {
      const value = Buffer.isBuffer(material) ? Buffer.from(material) : Buffer.from(material, "hex");
      if (value.length !== 32) throw new TypeError(`economic commitment key ${id} must contain 32 bytes`);
      return [id, value];
    }));
    if (!this.keys.has(keyId)) throw new TypeError("active economic commitment key is unavailable");
    this.keyId = keyId;
    this.version = "HMAC-SHA256-v1";
  }

  commit({ tenantId, transactionId, productId, field, value, keyId = this.keyId }) {
    const key = this.keys.get(keyId);
    if (!key) {
      const error = new Error(`economic commitment key ${keyId} is unavailable`);
      error.code = "UNKNOWN_ECONOMIC_COMMITMENT_KEY";
      throw error;
    }
    return createHmac("sha256", key).update(canonicalize({
      domain: "rwa.economic-commitment.v1", tenantId, transactionId, productId, field, value: String(value),
    })).digest("hex");
  }

  matches(context, expectedHex, keyId = this.keyId) {
    if (!/^[0-9a-f]{64}$/.test(expectedHex ?? "")) return false;
    return timingSafeEqual(Buffer.from(this.commit({ ...context, keyId }), "hex"), Buffer.from(expectedHex, "hex"));
  }
}

export class KmsEconomicCommitter {
  constructor({ provider, keyId }) {
    if (!provider || typeof provider.generateMac !== "function") {
      throw new TypeError("KMS economic commitment provider must implement generateMac");
    }
    if (!keyId) throw new TypeError("KMS economic commitment key id is required");
    this.provider = provider;
    this.keyId = keyId;
    this.version = "KMS-HMAC-SHA256-v1";
  }

  async commit({ tenantId, transactionId, productId, field, value, keyId = this.keyId }) {
    const message = Buffer.from(canonicalize({
      domain: "rwa.economic-commitment.v1", tenantId, transactionId, productId, field, value: String(value),
    }));
    const result = await this.provider.generateMac({ keyId, algorithm: "HMAC_SHA_256", message });
    const mac = Buffer.isBuffer(result) ? result : result?.mac;
    if (!Buffer.isBuffer(mac) || mac.length !== 32) {
      const error = new Error("KMS provider returned an invalid economic commitment MAC");
      error.code = "INVALID_KMS_MAC_RESPONSE";
      throw error;
    }
    return mac.toString("hex");
  }

  async matches(context, expectedHex, keyId = this.keyId) {
    if (!/^[0-9a-f]{64}$/.test(expectedHex ?? "")) return false;
    const actual = await this.commit({ ...context, keyId });
    return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expectedHex, "hex"));
  }
}
