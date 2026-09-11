import assert from "node:assert/strict";
import test from "node:test";
import { DemoRuntime } from "../src/demo-runtime.js";

function fixture() {
  const calls = [];
  const runtime = new DemoRuntime({
    config: { storageMode: "postgres", deploymentProfile: "production", authMode: "oidc", tenantId: "tenant-a" },
    productCatalogService: {
      async registerInstitutionSigningKey(input) { calls.push(input); return input; },
      async revokeInstitutionSigningKey(input) { calls.push(input); return input; },
    },
  });
  return { runtime, calls };
}

for (const operation of ["register", "revoke"]) {
  const invoke = (runtime, institutionId, input, identity) => operation === "register"
    ? runtime.registerCatalogInstitutionSigningKey(institutionId, input, identity)
    : runtime.revokeCatalogInstitutionSigningKey(institutionId, "key-1", input, identity);

  test(`${operation} institution signing key rejects cross-institution and incomplete server identities before storage`, async () => {
    const { runtime, calls } = fixture();
    const base = { tenantId: "tenant-a", principalId: "issuer-a", institutionId: "institution-a" };
    for (const identity of [base, { ...base, institutionId: undefined }, { ...base, institutionId: "" },
      { ...base, institutionId: "institution-b", tenantId: undefined }, undefined]) {
      await assert.rejects(invoke(runtime, "institution-b", {
        institutionId: "institution-b", tenantId: "tenant-a", reason: "test",
      }, identity), { code: "AUTHORIZATION_DENIED" });
    }
    await assert.rejects(invoke(runtime, "institution-a", {}, { ...base, tenantId: "tenant-b" }),
      { code: "TENANT_SCOPE_MISMATCH" });
    assert.equal(calls.length, 0);
  });

  test(`${operation} institution signing key forwards only the authenticated tenant and actor`, async () => {
    const { runtime, calls } = fixture();
    const identity = { tenantId: "tenant-a", principalId: "issuer-a", institutionId: "institution-a" };
    await invoke(runtime, "institution-a", { reason: "rotation", actorRef: "forged", tenantId: "forged" }, identity);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].institutionId, "institution-a");
    assert.equal(calls[0].tenantId, "tenant-a");
    assert.equal(calls[0].actorRef, "issuer-a");
  });
}
