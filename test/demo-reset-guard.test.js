import assert from "node:assert/strict";
import test from "node:test";
import { DurableWorkflowService } from "../src/storage/durable-workflow-service.js";

const evidence = {
  id: "nav-demo-001", productId: "hk-liquidity-sandbox", dataType: "nav",
  sourceInstitutionId: "demo-admin", trustTier: "A", schemaVersion: "1.0.0",
  effectiveAt: "2026-08-27T00:00:00.000Z", expiresAt: "2026-08-28T00:00:00.000Z",
  payload: { navPerUnit: "10000", currency: "HKD", synthetic: true }, signature: "test",
};

test("demo reset refuses every non-sandbox tenant before opening a transaction", async () => {
  const store = { async withSerializableTransaction() { throw new Error("must not be called"); } };
  const service = new DurableWorkflowService(store, { tenantId: "production-hk" });
  await assert.rejects(
    service.resetSandboxDemo({ productId: "hk-liquidity-sandbox", actorRef: "issuer", navEvidence: evidence }),
    { code: "SANDBOX_RESET_FORBIDDEN" },
  );
});

test("demo reset refuses a non-synthetic product before opening a transaction", async () => {
  const store = { async withSerializableTransaction() { throw new Error("must not be called"); } };
  const service = new DurableWorkflowService(store, { tenantId: "sandbox-hk" });
  await assert.rejects(
    service.resetSandboxDemo({ productId: "real-product", actorRef: "issuer", navEvidence: evidence }),
    { code: "SANDBOX_RESET_FORBIDDEN" },
  );
});

test("demo reset requires the fixed signed NAV envelope before opening a transaction", async () => {
  const store = { async withSerializableTransaction() { throw new Error("must not be called"); } };
  const service = new DurableWorkflowService(store, { tenantId: "sandbox-hk" });
  await assert.rejects(
    service.resetSandboxDemo({ productId: "hk-liquidity-sandbox", actorRef: "issuer", navEvidence: { ...evidence, id: "wrong" } }),
    { code: "INVALID_DEMO_EVIDENCE" },
  );
});
