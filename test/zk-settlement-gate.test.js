import assert from "node:assert/strict";
import test from "node:test";
import { ZkSettlementGate } from "../src/storage/zk-settlement-gate.js";

test("ZK settlement gate fails closed on unsafe adapter or verifier concurrency", () => {
  assert.throws(
    () => new ZkSettlementGate({}, { proofAdapter: { mode: "SANDBOX_NO_ZK_PROOF" } }),
    { code: "PRODUCTION_PROOF_ADAPTER_REQUIRED" },
  );
  const proofAdapter = { mode: "GROTH16_VERIFIED" };
  assert.throws(
    () => new ZkSettlementGate({}, { proofAdapter, maxConcurrentVerifications: 0 }),
    { code: "INVALID_VERIFIER_CONCURRENCY" },
  );
  assert.throws(
    () => new ZkSettlementGate({}, { proofAdapter, maxConcurrentVerifications: 33 }),
    { code: "INVALID_VERIFIER_CONCURRENCY" },
  );
  assert.doesNotThrow(() => new ZkSettlementGate({}, { proofAdapter, maxConcurrentVerifications: 2 }));
});
