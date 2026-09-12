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

test("outbox delivers one aggregate's events in enqueue order across retries, leases and dead letters", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 6 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `order-tenant-${suffix}`;
  const aggregate = `order-aggregate-${suffix}`;
  const ids = [1, 2, 3].map((index) => `order-${index}-${suffix}`);
  const claimIds = (rows) => rows.map((row) => row.id);
  try {
    // Enqueued in one transaction: sequence follows insert order.
    await store.withSerializableTransaction(async (client) => {
      for (const [index, id] of ids.entries()) {
        await store.enqueueOutbox(client, { id, tenantId, topic: "rwa.order.test", aggregateId: aggregate, payload: { step: index + 1 } });
      }
    });
    const other = `order-other-${suffix}`;
    await enqueue(store, { id: other, tenantId, topic: "rwa.order.test", aggregateId: `other-${suffix}`, payload: { step: 1 } });

    // Concurrent workers: at most one event of the aggregate is in flight, the unrelated aggregate is not blocked.
    const [a, b] = await Promise.all([
      store.claimOutboxBatch({ workerId: `w-a-${suffix}`, tenantId, limit: 10, leaseMs: 5_000 }),
      store.claimOutboxBatch({ workerId: `w-b-${suffix}`, tenantId, limit: 10, leaseMs: 5_000 }),
    ]);
    const claimed = [...a, ...b];
    assert.deepEqual(claimIds(claimed).sort(), [ids[0], other].sort());
    const firstOwner = claimed.find((row) => row.id === ids[0]).claimed_by;
    await store.markOutboxPublished({ id: other, workerId: claimed.find((row) => row.id === other).claimed_by });

    // A retry with backoff must not let step 2 overtake step 1.
    await store.markOutboxFailed({ id: ids[0], workerId: firstOwner, error: "downstream timeout", retryDelayMs: 1 });
    await pool.query("SELECT pg_sleep(0.01)");
    const retry = await store.claimOutboxBatch({ workerId: `w-c-${suffix}`, tenantId, limit: 10, leaseMs: 1 });
    assert.deepEqual(claimIds(retry), [ids[0]]);

    // An expired lease is reclaimed before later events.
    await pool.query("SELECT pg_sleep(0.01)");
    const reclaimed = await store.claimOutboxBatch({ workerId: `w-d-${suffix}`, tenantId, limit: 10, leaseMs: 5_000 });
    assert.deepEqual(claimIds(reclaimed), [ids[0]]);

    // A dead letter stops its aggregate until the replay is approved and executed.
    await store.markOutboxFailed({ id: ids[0], workerId: `w-d-${suffix}`, error: "poison", dead: true });
    assert.deepEqual(await store.claimOutboxBatch({ workerId: `w-e-${suffix}`, tenantId, limit: 10 }), []);
    const { OutboxOperationalMonitor } = await import("../../src/storage/outbox-monitor.js");
    const blocked = await new OutboxOperationalMonitor(store, { tenantId }).snapshot();
    assert.equal(blocked.blockedByDeadLetter, 2);
    assert.ok(blocked.alerts.some((alert) => alert.code === "OUTBOX_AGGREGATE_BLOCKED_BY_DEAD_LETTER"));
    const replay = await store.proposeDeadLetterReplay({
      requestId: `order-replay-${suffix}`, eventId: ids[0], tenantId, makerRef: "ops-maker", reason: "Poison message fixed downstream",
    });
    await store.decideDeadLetterReplay({ requestId: replay.requestId, checkerRef: "ops-checker", decision: "APPROVE" });

    const delivered = [];
    const dispatcher = new OutboxDispatcher({
      store, workerId: `w-f-${suffix}`, tenantId, leaseMs: 5_000,
      publish: async (event) => { delivered.push(event.id); },
    });
    while ((await dispatcher.dispatchBatch({ limit: 10 })).claimed > 0) { /* drain */ }
    assert.deepEqual(delivered, ids);
  } finally {
    await pool.end();
  }
});
