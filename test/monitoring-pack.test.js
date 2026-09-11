import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { once } from "node:events";
import test from "node:test";
import { buildPrometheusConfig } from "../src/monitoring-config.js";
import { createWorkerHealthServer } from "../src/storage/outbox-worker.js";
import { createProverHealthServer } from "../src/storage/prover-worker.js";
import { prometheusMetrics } from "../src/storage/outbox-monitor.js";
import { proverPrometheusMetrics } from "../src/storage/prover-monitor.js";
import { WebRequestMetrics } from "../src/observability/web-metrics.js";
import { RuntimeOperationalMonitor } from "../src/observability/runtime-monitor.js";

const operations = { backlog: 0, claimed: 0, active: 0, expiredLeases: 0, recentDead: 0,
  recentFailed: 0, oldestBacklogAgeMs: 0, alerts: [] };
const state = () => ({ running: true, ready: true, cycles: 1, published: 0, failed: 0, dead: 0,
  cycleErrors: 0, processed: 0, verified: 0, retryable: 0, lastError: null,
  lastCycleAt: new Date().toISOString(), lastSuccessAt: new Date().toISOString() });
const json = async (file) => JSON.parse(await readFile(new URL("../deploy/monitoring/" + file, import.meta.url), "utf8"));

test("monitoring config requires explicit safe deployment labels", () => {
  assert.throws(() => buildPrometheusConfig({}), /explicit bounded/);
  assert.throws(() => buildPrometheusConfig({ tenantId: "sandbox-hk", environment: "production" }), /sandbox/);
  assert.throws(() => buildPrometheusConfig({ tenantId: 'tenant",token="secret', environment: "test" }), /explicit bounded/);
  const config = buildPrometheusConfig({ tenantId: "tenant-a", environment: "production" });
  assert.equal(config.scrape_configs.length, 3);
  for (const job of config.scrape_configs) {
    assert.equal(job.metrics_path, "/metrics/prometheus");
    assert.deepEqual(job.static_configs[0].labels, { tenant: "tenant-a", environment: "production" });
    assert.equal(job.scrape_timeout, "5s");
  }
});

test("alert and dashboard queries reference actual exporter metrics without sensitive labels", async () => {
  const monitor = new RuntimeOperationalMonitor({ pool: { async query() { return { rows: [{ details_visible: true,
    connections: 1, max_connections: 100, database_bytes: 100, lock_waiters: 0, oldest_transaction_seconds: 0 }] }; } } });
  const exported = prometheusMetrics(state(), operations) + proverPrometheusMetrics(state(), operations)
    + new WebRequestMetrics().prometheus() + await monitor.prometheus();
  const names = new Set([...exported.matchAll(/^(rwa_[a-z_]+)[ {]/gm)].map((match) => match[1]));
  const { groups } = await json("rwa-alerts.yml");
  assert.equal(groups[0].rules.length, 22);
  const dashboard = await json("grafana/dashboards/rwa-operations.json");
  const expressions = [...groups.flatMap(g => g.rules.map((r) => r.expr)), ...dashboard.panels.flatMap((p) => (p.targets ?? []).map((t) => t.expr))];
  for (const expr of expressions) {
    for (const name of expr.match(/rwa_[a-z_]+/g) ?? []) assert.ok(names.has(name), name);
    assert.doesNotMatch(expr, /or vector\(0\)|sum.*backlog/);
  }
  assert.doesNotMatch(exported, /owner|witness|amount|transaction_id|secret|NaN|undefined/);
  for (const worker of ["Outbox", "Prover"]) {
    for (const suffix of ["TargetMissing", "ScrapeFailed", "MetricMissing", "NotReady", "TerminalFailures"]) {
      assert.ok(groups[0].rules.some((r) => r.alert === "Rwa" + worker + suffix));
    }
  }
  const datasource = await json("grafana/provisioning/datasources/rwa.yml");
  for (const panel of dashboard.panels.filter((p) => p.targets)) {
    assert.equal(panel.datasource.uid, datasource.datasources[0].uid);
  }
});

for (const [kind, create] of [["outbox", createWorkerHealthServer], ["prover", createProverHealthServer]]) {
  test(kind + " metrics distinguish ready, failed, stale and unavailable states", async () => {
    let snapshot = state();
    let failedMonitor = false;
    const server = create({ snapshot: () => snapshot }, {
      monitor: { async snapshot() { if (failedMonitor) throw new Error("synthetic unavailable"); return operations; } },
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const url = "http://127.0.0.1:" + server.address().port;
    try {
      const metrics = async () => (await fetch(url + "/metrics/prometheus")).text();
      assert.match(await metrics(), new RegExp("rwa_" + kind + "_worker_ready 1"));
      snapshot.lastError = "synthetic cycle error";
      assert.equal((await fetch(url + "/livez")).status, 200);
      assert.equal((await fetch(url + "/readyz")).status, 503);
      assert.match(await metrics(), new RegExp("rwa_" + kind + "_worker_ready 0"));
      snapshot = { ...state(), lastCycleAt: "2000-01-01T00:00:00Z", lastSuccessAt: "2000-01-01T00:00:00Z" };
      assert.match(await metrics(), new RegExp("rwa_" + kind + "_worker_ready 0"));
      snapshot = state();
      failedMonitor = true;
      assert.equal((await fetch(url + "/metrics/prometheus")).status, 503);
      assert.equal((await fetch(url + "/metrics")).status, 503);
      assert.equal((await fetch(url + "/livez")).status, 200);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
}
