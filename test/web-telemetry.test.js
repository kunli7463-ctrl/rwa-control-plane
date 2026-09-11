import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { WebRequestMetrics } from '../src/observability/web-metrics.js';
import { RuntimeOperationalMonitor, collectHostMetrics } from '../src/observability/runtime-monitor.js';
import { loadWebTelemetryConfig, createWebTelemetryServer } from '../src/observability/web-telemetry.js';

export const metricRow = { details_visible: true, connections: '2', max_connections: 100,
  lock_waiters: '0', oldest_transaction_seconds: '0', database_bytes: '1024' };

test('Web metrics count finish once, track aborts and never label private request data', () => {
  const metrics = new WebRequestMetrics();
  const response = new EventEmitter(); response.statusCode = 503; response.writableFinished = true;
  metrics.observe({ method: 'GET', url: '/private/secret?token=abc' }, response);
  response.emit('finish'); response.emit('close');
  const aborted = new EventEmitter();
  metrics.observe({ method: 'secret-method', url: '/private' }, aborted); aborted.emit('close');
  assert.equal(metrics.count, 1); assert.equal(metrics.aborted, 1); assert.equal(metrics.inFlight, 0);
  assert.match(metrics.prometheus(), /method="GET",status_class="5xx"} 1/);
  assert.doesNotMatch(metrics.prometheus(), /private|secret|token|abc|NaN/);
  assert.equal([...metrics.prometheus().matchAll(/^rwa_web_requests_total/gm)].length, 48);
});

test('metrics listener is opt-in and wildcard binding requires explicit private network acknowledgement', () => {
  assert.deepEqual(loadWebTelemetryConfig({}), { enabled: false });
  assert.throws(() => loadWebTelemetryConfig({ WEB_METRICS_ENABLED: 'yes' }));
  assert.throws(() => loadWebTelemetryConfig({ WEB_METRICS_ENABLED: 'true', WEB_METRICS_HOST: '0.0.0.0' }));
  assert.throws(() => loadWebTelemetryConfig({ WEB_METRICS_ENABLED: 'true', WEB_METRICS_PORT: '0' }));
  assert.equal(loadWebTelemetryConfig({ WEB_METRICS_ENABLED: 'true' }).host, '127.0.0.1');
});

test('runtime monitor collapses concurrent scrapes and drops stale details after database failure', async () => {
  let calls = 0, clock = 10000, fail = false;
  const monitor = new RuntimeOperationalMonitor({ now: () => clock, hostCollector: async () => ({}),
    pool: { async query() { calls++; if (fail) throw Error('password-secret'); return { rows: [metricRow] }; } } });
  await Promise.all([monitor.snapshot(), monitor.snapshot()]); assert.equal(calls, 1);
  assert.equal((await monitor.snapshot()).rwa_database_monitor_up, 1);
  clock += 6000; fail = true;
  const failed = await monitor.snapshot();
  assert.equal(failed.rwa_database_monitor_up, 0); assert.equal(failed.rwa_database_lock_waiters, undefined);
  assert.equal(failed.rwa_database_connections, undefined);
  assert.doesNotMatch(await monitor.prometheus(), /password|secret|NaN/);
  assert.throws(() => new RuntimeOperationalMonitor({ cacheMs: Infinity }));
});

test('restricted PostgreSQL visibility omits lock and long transaction gauges rather than claiming zero', async () => {
  const monitor = new RuntimeOperationalMonitor({ hostCollector: async () => { throw Error('host failure'); },
    pool: { async query() { return { rows: [{ ...metricRow, details_visible: false }] }; } } });
  const metrics = await monitor.snapshot();
  assert.equal(metrics.rwa_host_monitor_up, 0); assert.equal(metrics.rwa_database_monitor_up, 1);
  assert.equal(metrics.rwa_database_details_visible, 0);
  assert.equal(metrics.rwa_database_lock_waiters, undefined);
  assert.equal(metrics.rwa_database_oldest_transaction_seconds, undefined);
});

test('private HTTP exporter rejects unrelated paths and returns sanitized failure response', async () => {
  let fail = false;
  const server = createWebTelemetryServer({ requests: new WebRequestMetrics(), monitor: {
    async prometheus() { if (fail) throw Error('password-secret'); return 'rwa_host_monitor_up 1\n'; }
  } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const url = 'http://127.0.0.1:' + server.address().port;
    assert.equal((await fetch(url + '/')).status, 404);
    assert.equal((await fetch(url + '/metrics/prometheus')).status, 200);
    fail = true; const response = await fetch(url + '/metrics/prometheus');
    assert.equal(response.status, 503); assert.doesNotMatch(await response.text(), /password|secret/);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('host metrics use numeric fixed labels without disclosing filesystem paths', async () => {
  const metrics = await collectHostMetrics();
  assert.ok(metrics.rwa_host_memory_total_bytes > 0);
  assert.ok(metrics.rwa_runtime_filesystem_available_ratio >= 0);
  assert.ok(Object.values(metrics).every(Number.isFinite));
});
