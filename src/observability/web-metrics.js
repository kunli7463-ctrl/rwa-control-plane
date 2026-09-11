import { performance } from "node:perf_hooks";

const LIMITS = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
export class WebRequestMetrics {
  constructor() {
    this.counts = new Map(); this.buckets = LIMITS.map(() => 0);
    this.count = 0; this.sum = 0; this.inFlight = 0; this.aborted = 0;
  }
  observe(request, response) {
    // Neither store nor label raw URLs, IDs, headers or bodies.
    if ((request.url ?? "").split("?")[0].startsWith("/health/")) return;
    const method = METHODS.has(request.method) ? request.method : "OTHER";
    const start = performance.now();
    this.inFlight += 1;
    let complete = false;
    const finish = (aborted) => {
      if (complete) return;
      complete = true; this.inFlight -= 1;
      if (aborted) { this.aborted += 1; return; }
      const elapsed = Math.max(0, (performance.now() - start) / 1000);
      const code = Number(response.statusCode);
      const status = code >= 100 && code < 600 ? Math.floor(code / 100) + "xx" : "other";
      const key = method + ":" + status;
      this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
      this.count += 1; this.sum += elapsed;
      LIMITS.forEach((limit, index) => { if (elapsed <= limit) this.buckets[index] += 1; });
    };
    response.once("finish", () => finish(false));
    response.once("close", () => finish(!response.writableFinished));
  }
  prometheus() {
    const lines = ["# TYPE rwa_web_requests_total counter"];
    // Always export a bounded status family, including zeros after startup.
    for (const method of [...METHODS, "OTHER"]) for (const status of ["1xx","2xx","3xx","4xx","5xx","other"]) {
      lines.push('rwa_web_requests_total{method="' + method + '",status_class="' + status + '"} ' + (this.counts.get(method + ":" + status) ?? 0));
    }
    lines.push("# TYPE rwa_web_request_duration_seconds histogram");
    LIMITS.forEach((limit, index) => lines.push('rwa_web_request_duration_seconds_bucket{le="' + limit + '"} ' + this.buckets[index]));
    lines.push('rwa_web_request_duration_seconds_bucket{le="+Inf"} ' + this.count,
      "rwa_web_request_duration_seconds_count " + this.count,
      "rwa_web_request_duration_seconds_sum " + this.sum,
      "# TYPE rwa_web_in_flight gauge", "rwa_web_in_flight " + this.inFlight,
      "# TYPE rwa_web_aborted_requests_total counter", "rwa_web_aborted_requests_total " + this.aborted);
    return lines.join("\n") + "\n";
  }
}

