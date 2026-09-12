import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AuditChainCheckpointService } from "../../src/storage/audit-checkpoint-service.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");

test("audit chain checkpoints detect a deleted aggregate and record an external anchor", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  await runMigrations(store.pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `audit-tenant-${suffix}`;
  const service = new AuditChainCheckpointService(store, { tenantId });
  const record = (aggregateId, eventType) => store.withSerializableTransaction((client) => store.recordAuditEvent(client, {
    tenantId, eventType, aggregateType: "transaction", aggregateId, metadata: { suffix },
  }));
  try {
    await assert.rejects(service.createCheckpoint({ createdBy: "ops" }), { code: "NO_NEW_AUDIT_EVENTS" });
    for (const aggregate of ["alpha", "beta"]) {
      for (const eventType of ["transaction.requested", "transaction.settled"]) await record(`${aggregate}-${suffix}`, eventType);
    }
    const first = await service.createCheckpoint({ createdBy: "ops-maker" });
    assert.equal(first.checkpointNumber, 1);
    assert.equal(first.eventCount, "4");
    assert.equal(first.previousDigest, null);
    assert.match(first.digest, /^[0-9a-f]{64}$/);
    assert.deepEqual(await service.verifyCheckpoints(), {
      tenantId, valid: true, checkpoints: 1, eventCount: "4", latestDigest: first.digest, latestAnchor: null,
    });

    // Anchoring is what makes the digest externally provable; it is written once.
    const anchored = await service.recordExternalAnchor({
      checkpointNumber: 1, anchor: { service: "notary.example", reference: `receipt-${suffix}` },
    });
    assert.equal(anchored.digest, first.digest);
    await assert.rejects(service.recordExternalAnchor({
      checkpointNumber: 1, anchor: { service: "notary.example", reference: "second-attempt" },
    }), { code: "CHECKPOINT_ANCHOR_UNAVAILABLE" });
    await assert.rejects(service.recordExternalAnchor({ checkpointNumber: 1, anchor: { service: "notary.example" } }),
      { code: "INVALID_EXTERNAL_ANCHOR" });
    await assert.rejects(store.pool.query(
      "UPDATE rwa.audit_chain_checkpoints SET digest=repeat('0',64) WHERE tenant_id=$1", [tenantId]),
    { code: "55000" });
    await assert.rejects(store.pool.query("DELETE FROM rwa.audit_chain_checkpoints WHERE tenant_id=$1", [tenantId]),
      { code: "55000" });

    await record(`gamma-${suffix}`, "transaction.requested");
    const second = await service.createCheckpoint({ createdBy: "ops-maker" });
    assert.equal(second.previousDigest, first.digest);
    assert.equal(second.eventCount, "5");
    assert.equal((await service.verifyCheckpoints()).valid, true);

    // Removing every event of one aggregate leaves the per-aggregate chains intact
    // but breaks the anchored checkpoint.
    await store.pool.query("ALTER TABLE rwa.audit_events DISABLE TRIGGER append_only_guard");
    await store.pool.query("DELETE FROM rwa.audit_events WHERE tenant_id=$1 AND aggregate_id=$2", [tenantId, `beta-${suffix}`]);
    await store.pool.query("ALTER TABLE rwa.audit_events ENABLE TRIGGER append_only_guard");
    const tampered = await service.verifyCheckpoints();
    assert.equal(tampered.valid, false);
    assert.equal(tampered.reason, "EVENT_COUNT_MISMATCH");
    assert.equal(tampered.checkpointNumber, 1);
    assert.equal(tampered.anchored, true);
  } finally {
    await store.pool.query("ALTER TABLE rwa.audit_events ENABLE TRIGGER append_only_guard").catch(() => {});
    await store.close();
  }
});
