import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { OutboxDispatcher } from "../../src/storage/outbox-dispatcher.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

function boundedEnv(name, fallback, maximum) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

test("parallel Outbox workers publish a synthetic backlog once without stranded claims", { skip: !enabled }, async () => {
  const eventCount = boundedEnv("RWA_STRESS_EVENT_COUNT", 100, 5_000);
  const workerCount = boundedEnv("RWA_STRESS_WORKERS", 6, 32);
  const store = await PostgresStore.connect({
    connectionString: process.env.DATABASE_URL, max: Math.min(workerCount + 4, 40),
  });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `pressure-${suffix}`;
  const eventIds = Array.from({ length: eventCount }, (_, index) => `pressure-${index}-${suffix}`);
  const deliveries = new Map();
  try {
    await store.withSerializableTransaction(async (client) => {
      for (const [index, id] of eventIds.entries()) {
        await store.enqueueOutbox(client, {
          id, tenantId, topic: "rwa.pressure.synthetic", aggregateId: `aggregate-${index}-${suffix}`,
          payload: { schema: "rwa.pressure.synthetic.v1", sequence: index },
        });
      }
    });
    const workers = Array.from({ length: workerCount }, (_, index) => new OutboxDispatcher({
      store, workerId: `pressure-worker-${index}-${suffix}`, tenantId, leaseMs: 10_000,
      publish: async (event) => {
        deliveries.set(event.id, (deliveries.get(event.id) ?? 0) + 1);
        await new Promise((resolve) => setTimeout(resolve, index % 3));
      },
    }));

    for (let round = 0; round < 100 && deliveries.size < eventCount; round += 1) {
      await Promise.all(workers.map((worker) => worker.dispatchBatch({ limit: 25 })));
    }
    assert.equal(deliveries.size, eventCount);
    assert.equal([...deliveries.values()].every((count) => count === 1), true);
    const state = await store.pool.query(
      `SELECT status,count(*)::int AS count FROM rwa.outbox_events
       WHERE tenant_id=$1 GROUP BY status ORDER BY status`, [tenantId],
    );
    assert.deepEqual(state.rows, [{ status: "PUBLISHED", count: eventCount }]);
    const stranded = await store.pool.query(
      `SELECT count(*)::int AS count FROM rwa.outbox_events
       WHERE tenant_id=$1 AND (claimed_by IS NOT NULL OR lease_expires_at IS NOT NULL)`, [tenantId],
    );
    assert.equal(stranded.rows[0].count, 0);
  } finally {
    await store.close();
  }
});

