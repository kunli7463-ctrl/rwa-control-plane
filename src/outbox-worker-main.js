import { randomUUID } from "node:crypto";
import { OutboxDispatcher } from "./storage/outbox-dispatcher.js";
import { createOutboxPublisher } from "./outbox-publisher.js";
import { PostgresStore } from "./storage/postgres-store.js";
import { createWorkerHealthServer, OutboxWorker } from "./storage/outbox-worker.js";
import { OutboxOperationalMonitor } from "./storage/outbox-monitor.js";
import { validateOutboxWorkerDeployment } from "./production-preflight.js";

function positiveEnv(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required for the Outbox worker");
const deployment = validateOutboxWorkerDeployment(process.env);
const store = await PostgresStore.connect({ connectionString: databaseUrl });
const workerId = process.env.OUTBOX_WORKER_ID ?? `outbox-${process.pid}-${randomUUID()}`;
const deploymentProfile = deployment.deploymentProfile;
const tenantId = deployment.tenantId;
const publisher = await createOutboxPublisher({
  deploymentProfile,
  store,
  tenantId,
  modulePath: process.env.OUTBOX_PUBLISHER_MODULE,
});
const dispatcher = new OutboxDispatcher({
  store,
  workerId,
  tenantId,
  publish: publisher.publish,
  leaseMs: positiveEnv("OUTBOX_LEASE_MS", 30_000),
  maxAttempts: positiveEnv("OUTBOX_MAX_ATTEMPTS", 8),
  baseDelayMs: positiveEnv("OUTBOX_BASE_DELAY_MS", 1_000),
  maxDelayMs: positiveEnv("OUTBOX_MAX_DELAY_MS", 300_000),
});
const worker = new OutboxWorker({
  dispatcher,
  pollIntervalMs: positiveEnv("OUTBOX_POLL_INTERVAL_MS", 1_000),
  batchSize: positiveEnv("OUTBOX_BATCH_SIZE", 50),
});
const monitor = new OutboxOperationalMonitor(store, {
  tenantId,
  warningBacklog: positiveEnv("OUTBOX_WARNING_BACKLOG", 100),
  criticalBacklog: positiveEnv("OUTBOX_CRITICAL_BACKLOG", 1_000),
  warningOldestAgeMs: positiveEnv("OUTBOX_WARNING_AGE_MS", 60_000),
  criticalOldestAgeMs: positiveEnv("OUTBOX_CRITICAL_AGE_MS", 300_000),
});
const healthServer = createWorkerHealthServer(worker, {
  monitor, staleAfterMs: positiveEnv("OUTBOX_STALE_AFTER_MS", 60_000),
});
const healthPort = positiveEnv("OUTBOX_HEALTH_PORT", 8770);
const healthHost = process.env.OUTBOX_HEALTH_HOST ?? "127.0.0.1";
const shutdownTimeoutMs = positiveEnv("OUTBOX_SHUTDOWN_TIMEOUT_MS", 30_000);

healthServer.listen(healthPort, healthHost, () => {
  console.log(`Outbox worker ${workerId} (${tenantId}, ${publisher.mode}) health on http://${healthHost}:${healthPort}`);
});
worker.start();

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Outbox worker received ${signal}; draining current batch`);
  const forced = setTimeout(() => {
    console.error(`Outbox worker failed to drain within ${shutdownTimeoutMs}ms`);
    process.exit(1);
  }, shutdownTimeoutMs);
  forced.unref();
  try {
    await worker.stop();
    await new Promise((resolve) => healthServer.close(resolve));
    await store.close();
    clearTimeout(forced);
    process.exit(0);
  } catch (error) {
    console.error("Outbox worker shutdown failed", error);
    process.exit(1);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => shutdown(signal));
