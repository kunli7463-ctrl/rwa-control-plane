import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  AesGcmEnvelopeCipher, KmsEnvelopeCipher, LocalKeyring, SoftwareKmsProvider,
} from "../src/security/envelope-crypto.js";

const context = {
  tenantId: "tenant-a",
  transactionId: "tx-1",
  productId: "product-a",
  transactionType: "TRANSFER",
};

test("AES-GCM envelope round-trips and supports key rotation", () => {
  const oldKey = randomBytes(32);
  const newKey = randomBytes(32);
  const oldCipher = new AesGcmEnvelopeCipher(new LocalKeyring({ activeKeyId: "k1", keys: { k1: oldKey } }));
  const encoded = oldCipher.encrypt({ amount: "100", sellerId: "alice" }, context);
  const rotated = new AesGcmEnvelopeCipher(new LocalKeyring({ activeKeyId: "k2", keys: { k1: oldKey, k2: newKey } }));
  assert.deepEqual(rotated.decrypt(encoded, context), { amount: "100", sellerId: "alice" });
  assert.equal(JSON.parse(rotated.encrypt({ test: true }, context).toString("utf8")).kid, "k2");
});

test("AES-GCM envelope rejects ciphertext tampering and cross-transaction substitution", () => {
  const cipher = new AesGcmEnvelopeCipher(new LocalKeyring({ activeKeyId: "k1", keys: { k1: randomBytes(32) } }));
  const encoded = cipher.encrypt({ amount: "100" }, context);
  const envelope = JSON.parse(encoded.toString("utf8"));
  const bytes = Buffer.from(envelope.ciphertext, "base64");
  bytes[0] ^= 1;
  envelope.ciphertext = bytes.toString("base64");
  assert.throws(
    () => cipher.decrypt(Buffer.from(JSON.stringify(envelope)), context),
    { code: "CIPHERTEXT_AUTHENTICATION_FAILED" },
  );
  assert.throws(
    () => cipher.decrypt(encoded, { ...context, transactionId: "tx-2" }),
    { code: "CIPHERTEXT_AUTHENTICATION_FAILED" },
  );
});

test("keyring rejects missing and incorrectly sized keys", () => {
  assert.throws(() => new LocalKeyring({ activeKeyId: "missing", keys: {} }), { code: "UNKNOWN_ACTIVE_KEY" });
  assert.throws(() => new LocalKeyring({ activeKeyId: "bad", keys: { bad: "00" } }), { code: "INVALID_MASTER_KEY" });
});

test("KMS envelope uses a unique data key, binds context and survives wrapping-key rotation", async () => {
  const provider = new SoftwareKmsProvider({
    activeKeyId: "kms-k1", keys: { "kms-k1": randomBytes(32), "kms-k2": randomBytes(32) },
  });
  const cipher = new KmsEnvelopeCipher(provider);
  const context = { tenantId: "tenant-a", transactionId: "tx-1", productId: "product-a", transactionType: "TRANSFER" };
  const first = await cipher.encrypt({ amount: "100" }, context);
  const second = await cipher.encrypt({ amount: "100" }, context);
  assert.notDeepEqual(first, second);
  assert.deepEqual(await cipher.decrypt(first, context), { amount: "100" });
  await assert.rejects(cipher.decrypt(first, { ...context, transactionId: "tx-2" }), {
    code: "KMS_UNWRAP_FAILED",
  });
  provider.setActive("kms-k2");
  const rotated = await cipher.encrypt({ amount: "200" }, context);
  assert.deepEqual(await cipher.decrypt(first, context), { amount: "100" });
  assert.deepEqual(await cipher.decrypt(rotated, context), { amount: "200" });
});

test("disabled KMS keys fail closed without corrupting ciphertext", async () => {
  const provider = new SoftwareKmsProvider({ activeKeyId: "kms-k1", keys: { "kms-k1": randomBytes(32) } });
  const cipher = new KmsEnvelopeCipher(provider);
  const context = { tenantId: "tenant-a", transactionId: "tx-1", productId: "product-a", transactionType: "SUBSCRIBE" };
  const encrypted = await cipher.encrypt({ units: "10" }, context);
  provider.disable("kms-k1");
  await assert.rejects(cipher.decrypt(encrypted, context), { code: "KMS_KEY_UNAVAILABLE" });
  await assert.rejects(cipher.encrypt({ units: "20" }, context), { code: "KMS_KEY_UNAVAILABLE" });
});
