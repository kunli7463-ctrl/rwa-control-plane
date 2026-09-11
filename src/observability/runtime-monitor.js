import os from "node:os";
import { statfs } from "node:fs/promises";
import { performance } from "node:perf_hooks";

export const DATABASE_METRICS_SQL = `
SELECT pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') AS details_visible,
  (SELECT count(*) FROM pg_stat_activity WHERE datname IS NOT NULL) AS connections,
  current_setting('max_connections')::int AS max_connections,
  (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock') AS lock_waiters,
  (SELECT COALESCE(max(GREATEST(0,extract(epoch FROM clock_timestamp()-xact_start))),0)
     FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()) AS oldest_transaction_seconds,
  pg_database_size(current_database()) AS database_bytes
`;

const value = (input) => {
  const result = Number(input);
  if (input === null || input === undefined || !Number.isFinite(result) || result < 0) throw new Error("invalid metric");
  return result;
};

export async function collectHostMetrics({ filesystemPath = process.cwd() } = {}) {
  const disk = await statfs(filesystemPath);
  const cpu = os.cpus();
  const total = cpu.reduce((sum, core) => sum + Object.values(core.times).reduce((a, b) => a + b, 0), 0);
  const idle = cpu.reduce((sum, core) => sum + core.times.idle, 0);
  const memory = os.totalmem();
  if (!disk.blocks || !memory || !cpu.length) throw new Error("host metrics unavailable");
  return {
    rwa_host_memory_free_ratio: os.freemem() / memory,
    rwa_host_memory_total_bytes: memory,
    rwa_host_cpu_idle_seconds_total: idle / 1000,
    rwa_host_cpu_total_seconds_total: total / 1000,
    rwa_runtime_filesystem_available_ratio: Math.max(0, disk.bavail / disk.blocks),
    rwa_runtime_filesystem_available_bytes: Math.max(0, disk.bavail * disk.bsize),
  };
}

export class RuntimeOperationalMonitor {
  constructor({ pool = null, hostCollector = collectHostMetrics, cacheMs = 5000, now = () => Date.now() } = {}) {
    if (!Number.isFinite(cacheMs) || cacheMs < 0 || cacheMs > 15000) throw new Error("invalid metrics cache duration");
    this.pool = pool; this.hostCollector = hostCollector; this.cacheMs = cacheMs; this.now = now;
    this.cached = null; this.inFlight = null;
  }
  async snapshot() {
    if (this.cached && this.now() - this.cached.sampledAt < this.cacheMs) return this.cached.metrics;
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.collect();
    try {
      const metrics = await this.inFlight;
      this.cached = { sampledAt: this.now(), metrics };
      return metrics;
    } finally { this.inFlight = null; }
  }
  async collect() {
    const metrics = { rwa_database_monitor_enabled: this.pool ? 1 : 0 };
    try {
      const host = await this.hostCollector();
      for (const input of Object.values(host)) value(input);
      Object.assign(metrics, host, { rwa_host_monitor_up: 1 });
    } catch { metrics.rwa_host_monitor_up = 0; }
    if (this.pool) {
      const start = performance.now();
      try {
        const { rows } = await this.pool.query(DATABASE_METRICS_SQL);
        const row = rows[0];
        const db = {
          rwa_database_connections: value(row.connections),
          rwa_database_max_connections: value(row.max_connections),
          rwa_database_size_bytes: value(row.database_bytes),
          rwa_database_details_visible: row.details_visible === true ? 1 : 0,
        };
        if (row.details_visible === true) {
          db.rwa_database_lock_waiters = value(row.lock_waiters);
          db.rwa_database_oldest_transaction_seconds = value(row.oldest_transaction_seconds);
        }
        Object.assign(metrics, db, { rwa_database_monitor_up: 1 });
      } catch { metrics.rwa_database_monitor_up = 0; }
      metrics.rwa_database_probe_duration_seconds = (performance.now() - start) / 1000;
    }
    metrics.rwa_runtime_metrics_sample_timestamp_seconds = this.now() / 1000;
    return metrics;
  }
  async prometheus() {
    const metrics = { ...(await this.snapshot()), rwa_process_resident_memory_bytes: process.memoryUsage().rss,
      rwa_process_cpu_seconds_total: (process.cpuUsage().user + process.cpuUsage().system) / 1e6 };
    return Object.entries(metrics).map(([name, number]) => name + " " + value(number)).join("\n") + "\n";
  }
  async close() { if (this.pool) await this.pool.end(); }
}
