import assert from "node:assert/strict";
import test from "node:test";
import { OutboxWorker } from "../../src/storage/outbox-worker.js";
import { ProverWorker } from "../../src/storage/prover-worker.js";

function controlledOperation(result) {
  let enter;
  let release;
  const entered = new Promise((resolve) => { enter = resolve; });
  const blocked = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  return {
    entered,
    release,
    calls: () => calls,
    async run() {
      calls += 1;
      enter();
      await blocked;
      return result;
    },
  };
}

test("Outbox worker collapses a concurrent runOnce burst to one in-flight dispatch", async () => {
  const operation = controlledOperation({ claimed: 1, published: 1, failed: 0, dead: 0 });
  const worker = new OutboxWorker({
    dispatcher: { dispatchBatch: () => operation.run() }, pollIntervalMs: 1, batchSize: 50,
  });
  const first = worker.runOnce();
  await operation.entered;
  const burst = await Promise.all(Array.from({ length: 500 }, () => worker.runOnce()));
  assert.equal(burst.every((value) => value === null), true);
  assert.equal(operation.calls(), 1);
  operation.release();
  assert.deepEqual(await first, { claimed: 1, published: 1, failed: 0, dead: 0 });
  assert.equal(worker.snapshot().published, 1);
});

test("prover worker collapses a concurrent runOnce burst to one in-flight proof job", async () => {
  const operation = controlledOperation({ state: "VERIFIED" });
  const worker = new ProverWorker({
    workerId: "pressure-worker", pollIntervalMs: 100, runJob: () => operation.run(),
  });
  const first = worker.runOnce();
  await operation.entered;
  const burst = await Promise.all(Array.from({ length: 500 }, () => worker.runOnce()));
  assert.equal(burst.every((value) => value === null), true);
  assert.equal(operation.calls(), 1);
  operation.release();
  assert.deepEqual(await first, { state: "VERIFIED" });
  assert.equal(worker.snapshot().verified, 1);
});

