import { createServer } from "node:http";
import { proverPrometheusMetrics } from "./prover-monitor.js";

function delay(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

export class ProverWorker {
  constructor({ runJob, workerId, pollIntervalMs = 1_000, now = () => new Date() } = {}) {
    if (typeof runJob !== "function") throw new TypeError("runJob is required");
    if (typeof workerId !== "string" || !workerId) throw new TypeError("workerId is required");
    if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 100 || pollIntervalMs > 60_000) {
      throw new TypeError("pollIntervalMs must be between 100ms and 60000ms");
    }
    Object.assign(this, { runJob, workerId, pollIntervalMs, now });
    this.controller = null;
    this.loopPromise = null;
    this.metrics = { running: false, inFlight: false, cycles: 0, processed: 0, verified: 0,
      retryable: 0, failed: 0, cycleErrors: 0, startedAt: null, stoppedAt: null,
      lastCycleAt: null, lastSuccessAt: null, lastError: null };
  }

  start() {
    if (this.loopPromise) throw new Error("prover worker is already running");
    this.controller = new AbortController();
    this.metrics.running = true;
    this.metrics.startedAt = this.now().toISOString();
    this.loopPromise = this.#loop(this.controller.signal);
    return this.loopPromise;
  }

  async stop() {
    if (!this.loopPromise) return;
    this.controller.abort();
    await this.loopPromise;
  }

  async runOnce() {
    if (this.metrics.inFlight) return null;
    this.metrics.inFlight = true;
    this.metrics.lastCycleAt = this.now().toISOString();
    try {
      const result = await this.runJob(this.workerId);
      this.metrics.cycles += 1;
      if (result) {
        this.metrics.processed += 1;
        if (result.state === "VERIFIED") this.metrics.verified += 1;
        if (result.state === "RETRYABLE") this.metrics.retryable += 1;
        if (new Set(["FAILED", "CANCELLED"]).has(result.state)) this.metrics.failed += 1;
      }
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

  snapshot() { return { ...this.metrics }; }

  async #loop(signal) {
    try {
      while (!signal.aborted) {
        const result = await this.runOnce();
        if (!result && !signal.aborted) await delay(this.pollIntervalMs, signal);
      }
    } finally {
      this.metrics.running = false;
      this.metrics.stoppedAt = this.now().toISOString();
      this.loopPromise = null;
      this.controller = null;
    }
  }
}

export function createProverHealthServer(worker, { monitor, staleAfterMs = 60_000 } = {}) {
  if (!monitor || typeof monitor.snapshot !== "function") throw new TypeError("prover monitor is required");
  return createServer(async (request, response) => {
    const snapshot = worker.snapshot();
    const lastSuccessAge = snapshot.lastSuccessAt ? Date.now() - new Date(snapshot.lastSuccessAt).getTime() : Infinity;
    let operations = null;
    let monitorError = null;
    if (request.url !== "/livez") {
      try { operations = await monitor.snapshot(); } catch (error) { monitorError = error.message; }
    }
    const ready = snapshot.running && lastSuccessAge <= staleAfterMs && !snapshot.lastError && !monitorError;
    if (request.url === "/livez") {
      response.writeHead(snapshot.running ? 200 : 503, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ live: snapshot.running, running: snapshot.running }));
    }
    if (request.url === "/healthz" || request.url === "/readyz") {
      response.writeHead(ready ? 200 : 503, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ healthy: ready, ready, running: snapshot.running,
        inFlight: snapshot.inFlight, lastCycleAt: snapshot.lastCycleAt, monitorError, alerts: operations?.alerts ?? [] }));
    }
    if (request.url === "/metrics") {
      response.writeHead(monitorError ? 503 : 200, { "content-type": "application/json", "cache-control": "no-store" });
      return response.end(JSON.stringify({ worker: snapshot, operations, monitorError }));
    }
    if (request.url === "/metrics/prometheus") {
      response.writeHead(monitorError ? 503 : 200, { "content-type": "text/plain; version=0.0.4", "cache-control": "no-store" });
      return response.end(monitorError ? "# prover monitor unavailable\n" : proverPrometheusMetrics({ ...snapshot, ready }, operations));
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not found" }));
  });
}
