import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createProverHealthServer, ProverWorker } from "../src/storage/prover-worker.js";

test("prover worker records job outcomes and drains an in-flight job", async () => {
  let release;
  let entered;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  const releasePromise = new Promise((resolve) => { release = resolve; });
  const worker = new ProverWorker({
    workerId: "worker-a", pollIntervalMs: 100,
    runJob: async () => { entered(); await releasePromise; return { state: "VERIFIED" }; },
  });
  worker.start();
  await enteredPromise;
  const stopping = worker.stop();
  assert.equal(worker.snapshot().inFlight, true);
  release();
  await stopping;
  assert.deepEqual(Object.fromEntries(["running", "processed", "verified", "cycleErrors"].map((key) => [key, worker.snapshot()[key]])),
    { running: false, processed: 1, verified: 1, cycleErrors: 0 });
});

test("prover worker health and Prometheus endpoints fail closed with monitoring", async () => {
  const worker = new ProverWorker({ workerId: "worker-a", pollIntervalMs: 100, runJob: async () => null });
  const monitor = { async snapshot() { return { backlog: 0, active: 0, retryable: 0, recentFailed: 0,
    expiredLeases: 0, oldestBacklogAgeMs: 0, alerts: [] }; } };
  const server = createProverHealthServer(worker, { monitor, staleAfterMs: 5_000 });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  try {
    worker.start();
    for (let index = 0; index < 20 && worker.snapshot().cycles === 0; index += 1) await new Promise((resolve) => setTimeout(resolve, 2));
    assert.equal((await fetch(`http://127.0.0.1:${port}/readyz`)).status, 200);
    assert.match(await (await fetch(`http://127.0.0.1:${port}/metrics/prometheus`)).text(), /rwa_prover_worker_running 1/);
    await worker.stop();
    assert.equal((await fetch(`http://127.0.0.1:${port}/livez`)).status, 503);
  } finally {
    await worker.stop();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("prover readiness fails closed after an unexpected worker cycle error", async () => {
  const worker = new ProverWorker({
    workerId: "worker-error", pollIntervalMs: 100,
    runJob: async () => { throw new Error("database connection lost"); },
  });
  const monitor = { async snapshot() { return { backlog: 0, active: 0, retryable: 0, recentFailed: 0,
    expiredLeases: 0, oldestBacklogAgeMs: 0, alerts: [] }; } };
  const server = createProverHealthServer(worker, { monitor, staleAfterMs: 5_000 });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  try {
    worker.start();
    for (let index = 0; index < 20 && worker.snapshot().cycles === 0; index += 1) await new Promise((resolve) => setTimeout(resolve, 2));
    assert.equal((await fetch(`http://127.0.0.1:${port}/livez`)).status, 200);
    assert.equal((await fetch(`http://127.0.0.1:${port}/readyz`)).status, 503);
  } finally {
    await worker.stop();
    await new Promise((resolve) => server.close(resolve));
  }
});
