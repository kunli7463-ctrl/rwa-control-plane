import assert from "node:assert/strict";
import test from "node:test";
import { createOutboxPublisher } from "../src/outbox-publisher.js";

test("production Outbox refuses the simulated consumer and requires a tenant-scoped publisher", async () => {
  await assert.rejects(createOutboxPublisher({
    deploymentProfile: "production", tenantId: "sandbox-hk",
  }), { code: "PRODUCTION_TENANT_REQUIRED" });
  await assert.rejects(createOutboxPublisher({
    deploymentProfile: "production", tenantId: "tenant-a",
  }), { code: "OUTBOX_PUBLISHER_REQUIRED" });
});

test("production Outbox loads only an explicit publisher contract", async () => {
  const events = [];
  const publisher = await createOutboxPublisher({
    deploymentProfile: "production",
    tenantId: "tenant-a",
    modulePath: "provider.js",
    cwd: "/opt/rwa",
    importer: async (specifier) => {
      assert.equal(specifier, "/opt/rwa/provider.js");
      return {
        createOutboxPublisher: async ({ tenantId }) => ({
          async publish(event) { events.push({ tenantId, event }); },
        }),
      };
    },
  });
  assert.equal(publisher.mode, "EXTERNAL_AT_LEAST_ONCE");
  await publisher.publish({ id: "event-1" });
  assert.deepEqual(events, [{ tenantId: "tenant-a", event: { id: "event-1" } }]);
});

test("production Outbox rejects malformed publisher modules", async () => {
  const base = {
    deploymentProfile: "production", tenantId: "tenant-a", modulePath: "provider.js",
  };
  await assert.rejects(createOutboxPublisher({ ...base, importer: async () => ({}) }), {
    code: "INVALID_OUTBOX_PUBLISHER_MODULE",
  });
  await assert.rejects(createOutboxPublisher({
    ...base, importer: async () => ({ createOutboxPublisher: async () => ({}) }),
  }), { code: "INVALID_OUTBOX_PUBLISHER" });
});
