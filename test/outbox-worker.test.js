import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createWorkerHealthServer, OutboxWorker } from "../src/storage/outbox-worker.js";

test("outbox worker accumulates metrics and drains an in-flight batch on stop", async () => {
  let release;
  let entered;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  const releasePromise = new Promise((resolve) => { release = resolve; });
  const dispatcher = {
    async dispatchBatch() {
      entered();
      await releasePromise;
      return { claimed: 2, published: 1, failed: 1, dead: 0 };
    },
  };
  const worker = new OutboxWorker({ dispatcher, pollIntervalMs: 5, batchSize: 2 });
  worker.start();
  await enteredPromise;
  const stopPromise = worker.stop();
  assert.equal(worker.snapshot().inFlight, true);
  release();
  await stopPromise;
  assert.deepEqual(
    Object.fromEntries(["running", "inFlight", "cycles", "claimed", "published", "failed", "dead", "cycleErrors"].map((key) => [key, worker.snapshot()[key]])),
    { running: false, inFlight: false, cycles: 1, claimed: 2, published: 1, failed: 1, dead: 0, cycleErrors: 0 },
  );
  assert.ok(worker.snapshot().stoppedAt);
});

test("worker health and metrics endpoints reflect lifecycle", async () => {
  const dispatcher = { async dispatchBatch() { return { claimed: 0, published: 0, failed: 0, dead: 0 }; } };
  const worker = new OutboxWorker({ dispatcher, pollIntervalMs: 10 });
  const server = createWorkerHealthServer(worker, { staleAfterMs: 5_000 });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  try {
    worker.start();
    for (let index = 0; index < 20 && worker.snapshot().cycles === 0; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).healthy, true);
    const metrics = await (await fetch(`http://127.0.0.1:${port}/metrics`)).json();
    assert.equal(metrics.worker.running, true);
    assert.ok(metrics.worker.cycles >= 1);
    await worker.stop();
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 503);
  } finally {
    await worker.stop();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("worker readiness fails closed when PostgreSQL monitoring is unavailable", async () => {
  const dispatcher = { async dispatchBatch() { return { claimed: 0, published: 0, failed: 0, dead: 0 }; } };
  const worker = new OutboxWorker({ dispatcher, pollIntervalMs: 10 });
  const monitor = { async snapshot() { throw new Error("database unavailable"); } };
  const server = createWorkerHealthServer(worker, { staleAfterMs: 5_000, monitor });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  try {
    worker.start();
    for (let index = 0; index < 20 && worker.snapshot().cycles === 0; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.equal((await fetch(`http://127.0.0.1:${port}/livez`)).status, 200);
    const readiness = await fetch(`http://127.0.0.1:${port}/readyz`);
    assert.equal(readiness.status, 503);
    assert.equal((await readiness.json()).monitorError, "database unavailable");
    assert.equal((await fetch(`http://127.0.0.1:${port}/metrics/prometheus`)).status, 503);
  } finally {
    await worker.stop();
    await new Promise((resolve) => server.close(resolve));
  }
});
