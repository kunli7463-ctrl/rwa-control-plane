import { createServer } from "node:http";
import { once } from "node:events";
import { RuntimeOperationalMonitor, collectHostMetrics } from "./runtime-monitor.js";

export function loadWebTelemetryConfig(env = process.env) {
  if (![undefined, "true", "false"].includes(env.WEB_METRICS_ENABLED)) throw new Error("WEB_METRICS_ENABLED must be boolean text");
  if (env.WEB_METRICS_ENABLED !== "true") return { enabled: false };
  const host = env.WEB_METRICS_HOST ?? "127.0.0.1";
  const port = Number(env.WEB_METRICS_PORT ?? 8772);
  if (!["127.0.0.1", "::1", "0.0.0.0"].includes(host)
      || (host === "0.0.0.0" && env.WEB_METRICS_ALLOW_PRIVATE_NETWORK !== "true")
      || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("invalid private Web metrics bind contract");
  }
  return { enabled: true, host, port, filesystemPath: env.WEB_METRICS_FILESYSTEM_PATH ?? process.cwd(),
    databaseURL: env.RWA_MONITOR_DATABASE_URL ?? null };
}

export function createWebTelemetryServer({ requests, monitor }) {
  return createServer(async (req, res) => {
    if (req.method !== "GET" || req.url !== "/metrics/prometheus") { res.writeHead(404); return res.end(); }
    try {
      const text = requests.prometheus() + await monitor.prometheus();
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4", "cache-control": "no-store" }); res.end(text);
    } catch {
      res.writeHead(503, { "content-type": "text/plain", "cache-control": "no-store" }); res.end("# metrics unavailable\n");
    }
  });
}

export async function startWebTelemetry({ config, requests, databaseURL = null }) {
  if (!config.enabled) return null;
  let pool = null;
  if (config.databaseURL || databaseURL) {
    const { Pool } = await import("pg");
    pool = new Pool({ connectionString: config.databaseURL ?? databaseURL, max: 1,
      connectionTimeoutMillis: 1000, statement_timeout: 1000, query_timeout: 1500,
      options: "-c default_transaction_read_only=on", application_name: "rwa-readonly-metrics" });
    // Idle connection failures become monitor_up=0 on the next collection.
    pool.on("error", () => {});
  }
  const monitor = new RuntimeOperationalMonitor({ pool, hostCollector: () => collectHostMetrics({ filesystemPath: config.filesystemPath }) });
  const server = createWebTelemetryServer({ requests, monitor });
  server.listen(config.port, config.host);
  try { await once(server, "listening"); }
  catch (error) { await monitor.close(); throw error; }
  return { async close() {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve)); await monitor.close();
  } };
}

