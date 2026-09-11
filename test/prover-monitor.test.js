import assert from "node:assert/strict";
import test from "node:test";
import { ProverOperationalMonitor, proverPrometheusMetrics } from "../src/storage/prover-monitor.js";

test("prover monitor classifies backlog, delay, expired leases and recent failures", async () => {
  const store = { pool: { async query(_sql, parameters) {
    assert.deepEqual(parameters, ["tenant-a", 300_000]);
    return { rows: [{ backlog: 120, active: 3, retryable: 2, recent_failed: 1,
      expired_leases: 1, oldest_backlog_age_ms: "700000" }] };
  } } };
  const monitor = new ProverOperationalMonitor(store, { tenantId: "tenant-a" });
  const snapshot = await monitor.snapshot();
  assert.deepEqual(snapshot.alerts, [
    { severity: "CRITICAL", code: "PROVER_BACKLOG_HIGH", value: 120 },
    { severity: "CRITICAL", code: "PROVER_JOB_STALE", value: 700000 },
    { severity: "WARNING", code: "PROVER_EXPIRED_LEASES", value: 1 },
    { severity: "CRITICAL", code: "PROVER_RECENT_FAILURES", value: 1 },
  ]);
  assert.match(proverPrometheusMetrics({ running: true, cycles: 1, processed: 1, verified: 1,
    retryable: 0, failed: 0, cycleErrors: 0 }, snapshot), /rwa_prover_backlog 120/);
});

test("prover monitor rejects inverted alert thresholds", () => {
  assert.throws(() => new ProverOperationalMonitor({ pool: {} }, {
    tenantId: "tenant-a", warningBacklog: 10, criticalBacklog: 5,
  }), TypeError);
});
