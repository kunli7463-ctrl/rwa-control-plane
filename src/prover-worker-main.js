import { randomUUID } from "node:crypto";
import { DemoRuntime } from "./demo-runtime.js";
import { loadRuntimeConfig } from "./runtime-config.js";
import { ProverOperationalMonitor } from "./storage/prover-monitor.js";
import { createProverHealthServer, ProverWorker } from "./storage/prover-worker.js";

function positiveEnv(name, fallback, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

const config = loadRuntimeConfig();
const runtime = await DemoRuntime.create(config);
if (!runtime.proverJobService || !runtime.store) throw new Error("isolated prover worker requires PostgreSQL and PROVER_MODE=isolated");
const workerId = process.env.PROVER_WORKER_ID ?? `isolated-prover-worker:${process.pid}:${randomUUID()}`;
const tenantId = process.env.PROVER_TENANT_ID ?? runtime.tenantId;
if (tenantId !== runtime.tenantId) throw new Error("PROVER_TENANT_ID must match the runtime tenant");
const worker = new ProverWorker({
  workerId,
  pollIntervalMs: positiveEnv("PROVER_WORKER_POLL_MS", 1_000, 100, 60_000),
  runJob: (id) => runtime.runProverJobOnce(id),
});
const monitor = new ProverOperationalMonitor(runtime.store, {
  tenantId,
  warningBacklog: positiveEnv("PROVER_WARNING_BACKLOG", 20),
  criticalBacklog: positiveEnv("PROVER_CRITICAL_BACKLOG", 100),
  warningOldestAgeMs: positiveEnv("PROVER_WARNING_AGE_MS", 120_000),
  criticalOldestAgeMs: positiveEnv("PROVER_CRITICAL_AGE_MS", 600_000),
});
const healthServer = createProverHealthServer(worker, {
  monitor, staleAfterMs: positiveEnv("PROVER_STALE_AFTER_MS", 60_000),
});
const healthPort = positiveEnv("PROVER_HEALTH_PORT", 8771, 1, 65_535);
const healthHost = process.env.PROVER_HEALTH_HOST ?? "127.0.0.1";
const shutdownTimeoutMs = positiveEnv("PROVER_SHUTDOWN_TIMEOUT_MS", 30_000);

healthServer.listen(healthPort, healthHost, () => {
  console.log(`Isolated prover worker ${workerId} (${tenantId}) health on http://${healthHost}:${healthPort}`);
});
worker.start();

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Isolated prover worker received ${signal}; draining current job`);
  const forced = setTimeout(() => process.exit(1), shutdownTimeoutMs);
  forced.unref();
  try {
    await worker.stop();
    await new Promise((resolve) => healthServer.close(resolve));
    await runtime.close();
    clearTimeout(forced);
    process.exit(0);
  } catch (error) {
    console.error("Isolated prover worker shutdown failed", error);
    process.exit(1);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => shutdown(signal));
