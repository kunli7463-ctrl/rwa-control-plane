import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import {
  deriveEconomicCommitmentKey, EconomicCommitter, KmsEconomicCommitter,
} from "../src/security/economic-commitment.js";

test("economic commitments are domain separated, constant-size and rotation aware", () => {
  const oldKey = deriveEconomicCommitmentKey(Buffer.alloc(32, 1));
  const newKey = deriveEconomicCommitmentKey(Buffer.alloc(32, 2));
  const committer = new EconomicCommitter({
    keyId: "new", keys: { old: oldKey, new: newKey },
  });
  const base = { tenantId: "tenant", transactionId: "tx", productId: "product", field: "units", value: "10" };
  const oldCommitment = committer.commit({ ...base, keyId: "old" });
  const newCommitment = committer.commit(base);
  assert.match(oldCommitment, /^[0-9a-f]{64}$/);
  assert.notEqual(oldCommitment, newCommitment);
  assert.notEqual(newCommitment, committer.commit({ ...base, field: "cashAmountMinor" }));
  assert.notEqual(newCommitment, committer.commit({ ...base, transactionId: "other" }));
  assert.equal(committer.matches(base, oldCommitment, "old"), true);
  assert.equal(committer.matches({ ...base, value: "11" }, oldCommitment, "old"), false);
  assert.throws(() => committer.commit({ ...base, keyId: "missing" }), { code: "UNKNOWN_ECONOMIC_COMMITMENT_KEY" });
});

test("KMS economic commitments bind context without exposing a process-local HMAC key", async () => {
  const calls = [];
  const provider = {
    async generateMac({ keyId, algorithm, message }) {
      calls.push({ keyId, algorithm, message: message.toString("utf8") });
      return { mac: createHmac("sha256", Buffer.alloc(32, 7)).update(message).digest() };
    },
  };
  const committer = new KmsEconomicCommitter({ provider, keyId: "kms-mac-v1" });
  const base = {
    tenantId: "tenant-a", transactionId: "tx-1", productId: "product-a", field: "units", value: "10",
  };
  const commitment = await committer.commit(base);
  assert.match(commitment, /^[0-9a-f]{64}$/);
  assert.equal(await committer.matches(base, commitment), true);
  assert.equal(await committer.matches({ ...base, transactionId: "tx-2" }, commitment), false);
  assert.equal(calls[0].keyId, "kms-mac-v1");
  assert.equal(calls[0].algorithm, "HMAC_SHA_256");
  assert.match(calls[0].message, /rwa\.economic-commitment\.v1/);
});
