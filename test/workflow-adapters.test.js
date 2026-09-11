import assert from "node:assert/strict";
import test from "node:test";
import { assertWorkflowAdapter, MemoryWorkflowAdapter, PostgresWorkflowAdapter } from "../src/workflow-adapters.js";

test("workflow adapters expose the same asynchronous settlement contract", async () => {
  const calls = [];
  const plane = Object.fromEntries(["subscribe", "transfer", "redeem"].map((method) => [
    method,
    (command) => { calls.push([method, command.id]); return { transactionId: command.id }; },
  ]));
  const memory = assertWorkflowAdapter(new MemoryWorkflowAdapter(plane));
  const postgres = assertWorkflowAdapter(new PostgresWorkflowAdapter(plane));

  assert.deepEqual(await memory.subscribe({ id: "memory-1" }), { transactionId: "memory-1" });
  assert.deepEqual(await postgres.transfer({ id: "postgres-1" }), { transactionId: "postgres-1" });
  assert.deepEqual(calls, [["subscribe", "memory-1"], ["transfer", "postgres-1"]]);
});

test("invalid workflow adapters fail at startup", () => {
  assert.throws(() => assertWorkflowAdapter({ subscribe() {} }), /missing transfer/);
});
