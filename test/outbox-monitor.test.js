import assert from "node:assert/strict";
import test from "node:test";
import { OutboxOperationalMonitor, prometheusMetrics } from "../src/storage/outbox-monitor.js";

test("outbox monitor classifies backlog, stale events, expired leases and dead letters", async () => {
  const store = { pool: { async query(_sql, parameters) {
    assert.deepEqual(parameters, ["tenant-a", 300_000]);
    return { rows: [{ backlog: 1200, claimed: 3, expired_leases: 2, recent_dead: 1,
      oldest_backlog_age_ms: "360000" }] };
  } } };
  const monitor = new OutboxOperationalMonitor(store, { tenantId: "tenant-a" });
  const snapshot = await monitor.snapshot();
  assert.deepEqual(snapshot.alerts, [
    { severity: "CRITICAL", code: "OUTBOX_BACKLOG_HIGH", value: 1200 },
    { severity: "CRITICAL", code: "OUTBOX_OLDEST_EVENT_STALE", value: 360000 },
    { severity: "WARNING", code: "OUTBOX_EXPIRED_LEASES", value: 2 },
    { severity: "CRITICAL", code: "OUTBOX_RECENT_DEAD_LETTERS", value: 1 },
  ]);
  const metrics = prometheusMetrics({ running: true, cycles: 2, published: 3, failed: 1, dead: 1,
    cycleErrors: 0 }, snapshot);
  assert.match(metrics, /rwa_outbox_worker_running 1/);
  assert.match(metrics, /rwa_outbox_backlog 1200/);
  assert.match(metrics, /rwa_outbox_recent_dead_letters 1/);
});

test("outbox monitor rejects inverted thresholds", () => {
  const store = { pool: {} };
  assert.throws(() => new OutboxOperationalMonitor(store, { warningBacklog: 10, criticalBacklog: 5 }), TypeError);
});

