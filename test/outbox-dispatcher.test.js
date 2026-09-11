import assert from "node:assert/strict";
import test from "node:test";
import { retryDelayMs } from "../src/storage/outbox-dispatcher.js";

test("outbox retry delay is exponential and capped", () => {
  assert.equal(retryDelayMs(1), 1_000);
  assert.equal(retryDelayMs(2), 2_000);
  assert.equal(retryDelayMs(20), 300_000);
  assert.equal(retryDelayMs(5, { baseDelayMs: 10, maxDelayMs: 100 }), 100);
  assert.throws(() => retryDelayMs(0), /positive integer/);
});
