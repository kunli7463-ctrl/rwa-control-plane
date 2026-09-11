import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { OutboxDispatcher, SimulatedRegisterCallbackConsumer } from "../../src/storage/outbox-dispatcher.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

async function enqueue(store, event) {
  return store.withSerializableTransaction((client) => store.enqueueOutbox(client, event));
}

test("outbox leases, retries, dead letters and idempotent register callbacks survive failures", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `outbox-tenant-${suffix}`;

  try {
    const successId = `outbox-success-${suffix}`;
    await enqueue(store, {
      id: successId,
      tenantId,
      topic: "rwa.transaction.settled",
      aggregateId: `transaction-${suffix}`,
      payload: { transactionId: `transaction-${suffix}`, state: "SETTLED" },
    });
    const consumer = new SimulatedRegisterCallbackConsumer({ store, consumerName: `register-${suffix}` });
    const successDispatcher = new OutboxDispatcher({
      store,
      workerId: `worker-success-${suffix}`,
      tenantId,
      publish: (event) => consumer.consume(event),
      leaseMs: 5_000,
    });
    assert.deepEqual(await successDispatcher.dispatchBatch({ limit: 1 }), {
      claimed: 1, published: 1, failed: 0, dead: 0,
    });
    const published = await pool.query("SELECT * FROM rwa.outbox_events WHERE id=$1", [successId]);
    assert.equal(published.rows[0].status, "PUBLISHED");
    assert.equal(published.rows[0].claimed_by, null);
    const duplicate = await consumer.consume(published.rows[0]);
    assert.equal(duplicate.duplicate, true);
    const deliveryCounts = await pool.query(
      `SELECT
         (SELECT count(*)::int FROM rwa.inbox_consumptions WHERE event_id=$1) AS inbox_count,
         (SELECT count(*)::int FROM rwa.register_callback_events WHERE event_id=$1) AS callback_count`,
      [successId],
    );
    assert.deepEqual(deliveryCounts.rows[0], { inbox_count: 1, callback_count: 1 });

    const failedId = `outbox-failed-${suffix}`;
    await enqueue(store, {
      id: failedId,
      tenantId,
      topic: "rwa.transaction.settled",
      aggregateId: `failed-transaction-${suffix}`,
      payload: { transactionId: `failed-transaction-${suffix}`, state: "SETTLED" },
    });
    const failingDispatcher = new OutboxDispatcher({
      store,
      workerId: `worker-fail-${suffix}`,
      tenantId,
      publish: async () => { throw new Error("simulated downstream outage"); },
      leaseMs: 5_000,
      maxAttempts: 2,
      baseDelayMs: 1,
      maxDelayMs: 1,
    });
    assert.deepEqual(await failingDispatcher.dispatchBatch({ limit: 1 }), {
      claimed: 1, published: 0, failed: 1, dead: 0,
    });
    await pool.query("SELECT pg_sleep(0.01)");
    assert.deepEqual(await failingDispatcher.dispatchBatch({ limit: 1 }), {
      claimed: 1, published: 0, failed: 0, dead: 1,
    });
    const dead = await pool.query(
      "SELECT status,attempts,last_error,dead_lettered_at FROM rwa.outbox_events WHERE id=$1",
      [failedId],
    );
    assert.equal(dead.rows[0].status, "DEAD");
    assert.equal(dead.rows[0].attempts, 2);
    assert.match(dead.rows[0].last_error, /downstream outage/);
    assert.ok(dead.rows[0].dead_lettered_at);

    const replay = await store.proposeDeadLetterReplay({
      requestId: `replay-${suffix}`,
      eventId: failedId,
      tenantId,
      makerRef: "operations-maker",
      reason: "Downstream service recovered after incident review",
    });
    assert.equal(replay.state, "PENDING");
    await assert.rejects(
      store.decideDeadLetterReplay({ requestId: replay.requestId, checkerRef: "operations-maker", decision: "APPROVE" }),
      { code: "MAKER_CHECKER_CONFLICT" },
    );
    const approved = await store.decideDeadLetterReplay({
      requestId: replay.requestId,
      checkerRef: "operations-checker",
      decision: "APPROVE",
    });
    assert.equal(approved.state, "EXECUTED");
    const replayDispatcher = new OutboxDispatcher({
      store,
      workerId: `worker-replay-${suffix}`,
      tenantId,
      publish: (event) => consumer.consume(event),
      leaseMs: 5_000,
    });
    assert.deepEqual(await replayDispatcher.dispatchBatch({ limit: 1 }), {
      claimed: 1, published: 1, failed: 0, dead: 0,
    });
    const replayed = await pool.query(
      "SELECT status,attempts,replay_count,last_error FROM rwa.outbox_events WHERE id=$1",
      [failedId],
    );
    assert.deepEqual(replayed.rows[0], { status: "PUBLISHED", attempts: 1, replay_count: 1, last_error: null });
    const replayRequest = await pool.query(
      "SELECT status,maker_ref,checker_ref,checker_decision FROM rwa.dead_letter_replay_requests WHERE id=$1",
      [replay.requestId],
    );
    assert.deepEqual(replayRequest.rows[0], {
      status: "EXECUTED", maker_ref: "operations-maker", checker_ref: "operations-checker", checker_decision: "APPROVE",
    });

    const leasedId = `outbox-lease-${suffix}`;
    await enqueue(store, {
      id: leasedId,
      tenantId,
      topic: "rwa.lease.test",
      aggregateId: leasedId,
      payload: { transactionId: leasedId },
    });
    const firstClaim = await store.claimOutboxBatch({ workerId: `worker-old-${suffix}`, tenantId, limit: 1, leaseMs: 1 });
    assert.equal(firstClaim[0].id, leasedId);
    await pool.query("SELECT pg_sleep(0.01)");
    const reclaimed = await store.claimOutboxBatch({ workerId: `worker-new-${suffix}`, tenantId, limit: 1, leaseMs: 5_000 });
    assert.equal(reclaimed[0].id, leasedId);
    assert.equal(reclaimed[0].attempts, 2);
    await assert.rejects(
      store.markOutboxPublished({ id: leasedId, workerId: `worker-old-${suffix}` }),
      { code: "OUTBOX_CLAIM_MISMATCH" },
    );
    await store.markOutboxPublished({ id: leasedId, workerId: `worker-new-${suffix}` });
  } finally {
    await pool.end();
  }
});
