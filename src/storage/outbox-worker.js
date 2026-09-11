import { createServer } from "node:http";
import { prometheusMetrics } from "./outbox-monitor.js";

function delay(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}

export class OutboxWorker {
  constructor({ dispatcher, pollIntervalMs = 1_000, batchSize = 50, now = () => new Date() }) {
    if (!dispatcher || typeof dispatcher.dispatchBatch !== "function") throw new TypeError("dispatcher is required");
    if (!Number.isInteger(pollIntervalMs) || pollIntervalMs <= 0) throw new TypeError("pollIntervalMs must be positive");
    if (!Number.isInteger(batchSize) || batchSize <= 0) throw new TypeError("batchSize must be positive");
    this.dispatcher = dispatcher;
    this.pollIntervalMs = pollIntervalMs;
    this.batchSize = batchSize;
    this.now = now;
    this.abortController = null;
    this.loopPromise = null;
    this.metrics = {
      running: false, inFlight: false, cycles: 0, claimed: 0, published: 0, failed: 0, dead: 0,
      cycleErrors: 0, startedAt: null, stoppedAt: null, lastCycleAt: null, lastSuccessAt: null, lastError: null,
    };
  }

  start() {
    if (this.loopPromise) throw new Error("outbox worker is already running");
    this.abortController = new AbortController();
    this.metrics.running = true;
    this.metrics.startedAt = this.now().toISOString();
    this.metrics.stoppedAt = null;
    this.loopPromise = this.#loop(this.abortController.signal);
    return this.loopPromise;
  }

  async stop() {
    if (!this.loopPromise) return;
    this.abortController.abort();
    await this.loopPromise;
  }

  async runOnce() {
    if (this.metrics.inFlight) return null;
    this.metrics.inFlight = true;
    this.metrics.lastCycleAt = this.now().toISOString();
    try {
      const result = await this.dispatcher.dispatchBatch({ limit: this.batchSize });
      this.metrics.cycles += 1;
      for (const key of ["claimed", "published", "failed", "dead"]) this.metrics[key] += result[key];
      this.metrics.lastSuccessAt = this.now().toISOString();
      this.metrics.lastError = null;
      return result;
    } catch (error) {
      this.metrics.cycles += 1;
      this.metrics.cycleErrors += 1;
      this.metrics.lastError = error instanceof Error ? error.message : String(error);
      return null;
    } finally {
      this.metrics.inFlight = false;
    }
  }

  snapshot() {
    return { ...this.metrics };
  }

  async #loop(signal) {
    try {
      while (!signal.aborted) {
        const result = await this.runOnce();
        if (signal.aborted) break;
        if (!result || result.claimed === 0) await delay(this.pollIntervalMs, signal);
      }
    } finally {
      this.metrics.running = false;
      this.metrics.stoppedAt = this.now().toISOString();
      this.loopPromise = null;
      this.abortController = null;
    }
  }
}

export function createWorkerHealthServer(worker, { staleAfterMs = 60_000, monitor = null } = {}) {
  return createServer(async (request, response) => {
    const snapshot = worker.snapshot();
    const lastCycleAge = snapshot.lastCycleAt ? Date.now() - new Date(snapshot.lastCycleAt).getTime() : Infinity;
    const live = snapshot.running;
    let operations = null;
    let monitorError = null;
    if (monitor && new Set(["/healthz", "/readyz", "/metrics", "/metrics/prometheus"]).has(request.url)) {
      try { operations = await monitor.snapshot(); } catch (error) { monitorError = error.message; }
    }
    const ready = live && lastCycleAge <= staleAfterMs && !snapshot.lastError && !monitorError;
    if (request.url === "/livez") {
      response.writeHead(live ? 200 : 503, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ live, running: snapshot.running }));
    }
    if (request.url === "/healthz" || request.url === "/readyz") {
      response.writeHead(ready ? 200 : 503, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ healthy: ready, ready, running: snapshot.running, inFlight: snapshot.inFlight,
        lastCycleAt: snapshot.lastCycleAt, lastCycleAgeMs: Number.isFinite(lastCycleAge) ? lastCycleAge : null,
        monitorError, alerts: operations?.alerts ?? [] }));
    }
    if (request.url === "/metrics") {
      response.writeHead(monitorError ? 503 : 200, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ worker: snapshot, operations, monitorError }));
    }
    if (request.url === "/metrics/prometheus") {
      response.writeHead(monitorError ? 503 : 200, { "content-type": "text/plain; version=0.0.4", "cache-control": "no-store" });
      return response.end(monitorError ? "# outbox monitor unavailable\n" : prometheusMetrics({ ...snapshot, ready }, operations));
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not found" }));
  });
}
