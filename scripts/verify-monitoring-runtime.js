import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { access, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { buildPrometheusConfig } from "../src/monitoring-config.js";
import { prometheusMetrics } from "../src/storage/outbox-monitor.js";
import { proverPrometheusMetrics } from "../src/storage/prover-monitor.js";
import { WebRequestMetrics } from "../src/observability/web-metrics.js";
import { RuntimeOperationalMonitor } from "../src/observability/runtime-monitor.js";

// Isolated, synthetic-only pipeline verification. Never uses DATABASE_URL.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tools = path.join(root, ".local-tools");
const prom = process.env.RWA_PROMETHEUS_BIN ?? path.join(tools, "prometheus-3.14.0.darwin-arm64/prometheus");
const am = process.env.RWA_ALERTMANAGER_BIN ?? path.join(tools, "alertmanager-0.34.0.darwin-arm64/alertmanager");
const grafanaHome = process.env.RWA_GRAFANA_HOME ?? path.join(tools, "grafana-13.2.1");
const grafana = path.join(grafanaHome, "bin/grafana");
await Promise.all([prom, am, grafana].map((file) => access(file)));
await mkdir(path.join(root, ".local"), { recursive: true });
const run = await mkdtemp(path.join(root, ".local/monitoring-runtime-"));
const children = [];
const servers = [];
const events = [];
const report = { mode: "SYNTHETIC_LOCAL_ONLY", checks: [], productionPaging: false, startedAt: new Date().toISOString() };
const adminPassword = randomBytes(32).toString("hex");
const receiverToken = randomBytes(32).toString("hex");
const headers = { authorization: "Basic " + Buffer.from("admin:" + adminPassword).toString("base64") };
const visualSeconds = Number(process.env.RWA_VISUAL_REVIEW_SECONDS ?? 0);
if (!Number.isInteger(visualSeconds) || visualSeconds < 0 || visualSeconds > 900) throw new Error("visual review window must be 0..900 seconds");
const jsonFile = async (file, data) => writeFile(file, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
const record = (check) => { report.checks.push(check); console.log("PASS " + check); };
async function listen(server) {
  servers.push(server); server.listen(0, "127.0.0.1"); await once(server, "listening");
  return server.address().port;
}
async function port() {
  const server = createServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const result = server.address().port; await new Promise((resolve) => server.close(resolve)); return result;
}
function start(name, binary, args, env = {}) {
  const child = spawn(binary, args, { cwd: root, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  const entry = { name, child, log: "", stopped: false };
  child.on("error", (error) => { entry.error = error; });
  for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { entry.log = (entry.log + chunk).slice(-12000); });
  children.push(entry); return entry;
}
async function waitFor(label, operation, timeout = 45000) {
  const deadline = Date.now() + timeout;
  let last = "";
  while (Date.now() < deadline) {
    for (const item of children) if (item.error || item.child.exitCode !== null || item.child.signalCode !== null) {
      throw new Error(item.name + " exited: " + (item.error?.message ?? item.log));
    }
    try { if (await operation()) return; } catch (error) { last = error.message; }
    await delay(300);
  }
  throw new Error(label + " timed out: " + last);
}
const get = (url, options = {}) => fetch(url, { ...options, signal: AbortSignal.timeout(3000) });
const query = async (url, expr) => {
  const response = await get(url + "/api/v1/query?query=" + encodeURIComponent(expr));
  assert.equal(response.status, 200);
  const body = await response.json(); assert.equal(body.status, "success"); return body.data.result;
};

try {
  let ready = true;
  let exporterAvailable = true;
  const worker = () => ({ running: true, ready, cycles: 10, published: 2, failed: 0, dead: 0,
    cycleErrors: 0, processed: 2, verified: 2, retryable: 0 });
  const ops = { backlog: 0, claimed: 0, active: 0, expiredLeases: 0, recentDead: 0,
    recentFailed: 0, oldestBacklogAgeMs: 0 };
  const webRequests = new WebRequestMetrics();
  const runtimeMonitor = new RuntimeOperationalMonitor({ pool: { async query() { return { rows: [{ details_visible: true,
    connections: 2, max_connections: 100, database_bytes: 1024, lock_waiters: 0, oldest_transaction_seconds: 0 }] }; } } });
  const exporterPort = await listen(createServer(async (req, res) => {
    if (!exporterAvailable) { res.writeHead(503); return res.end("synthetic outage"); }
    res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
    res.end(req.url === "/web" ? webRequests.prometheus() + await runtimeMonitor.prometheus()
      : req.url === "/outbox" ? prometheusMetrics(worker(), ops) : proverPrometheusMetrics({ ...worker(), ready: true }, ops));
  }));
  const receiverPort = await listen(createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/alerts" || req.headers.authorization !== "Bearer " + receiverToken) {
      res.writeHead(403); return res.end();
    }
    try {
      let body = "";
      for await (const chunk of req) { body += chunk; if (body.length > 65536) { res.writeHead(413); return res.end(); } }
      const event = JSON.parse(body);
      events.push({ status: event.status, alerts: event.alerts.map((a) => ({ status: a.status, name: a.labels.alertname })) });
      res.writeHead(200); res.end("accepted");
    } catch { res.writeHead(400); res.end(); }
  }));
  const [promPort, amPort, grafanaPort] = await Promise.all([port(), port(), port()]);
  const promURL = "http://127.0.0.1:" + promPort;
  const amURL = "http://127.0.0.1:" + amPort;
  const grafanaURL = "http://127.0.0.1:" + grafanaPort;
  const sourceRules = JSON.parse(await readFile(path.join(root, "deploy/monitoring/rwa-alerts.yml"), "utf8"));
  const selected = structuredClone(sourceRules.groups[0].rules.find((r) => r.alert === "RwaOutboxNotReady"));
  // Production duration is independently tested by promtool. Shorten ONLY this
  // isolated end-to-end fixture to exercise transport without a minute's delay.
  selected.for = "1s";
  await jsonFile(path.join(run, "smoke-rules.yml"), { groups: [{ name: "synthetic-smoke", rules: [selected] }] });
  const config = buildPrometheusConfig({ tenantId: "sandbox-monitoring", environment: "test" });
  config.global = { scrape_interval: "1s", evaluation_interval: "1s" };
  config.rule_files = [path.join(run, "smoke-rules.yml")];
  config.alerting = { alertmanagers: [{ static_configs: [{ targets: ["127.0.0.1:" + amPort] }] }] };
  for (const job of config.scrape_configs) {
    job.scrape_timeout = "1s"; job.metrics_path = "/" + job.job_name.replace("rwa-", "");
    job.static_configs[0].targets = ["127.0.0.1:" + exporterPort];
  }
  await jsonFile(path.join(run, "prometheus.yml"), config);
  await jsonFile(path.join(run, "alertmanager.yml"), {
    global: { resolve_timeout: "5s" },
    route: { receiver: "local-only", group_by: ["alertname"], group_wait: "1s", group_interval: "1s", repeat_interval: "1m" },
    receivers: [{ name: "local-only", webhook_configs: [{
      url: "http://127.0.0.1:" + receiverPort + "/alerts", send_resolved: true,
      http_config: { authorization: { type: "Bearer", credentials: receiverToken } },
    }] }],
  });
  const provisioning = path.join(run, "provisioning");
  await mkdir(path.join(provisioning, "datasources"), { recursive: true });
  await mkdir(path.join(provisioning, "dashboards"), { recursive: true });
  const datasource = JSON.parse(await readFile(path.join(root, "deploy/monitoring/grafana/provisioning/datasources/rwa.yml"), "utf8"));
  datasource.datasources[0].url = promURL;
  await jsonFile(path.join(provisioning, "datasources/rwa.yml"), datasource);
  const provider = JSON.parse(await readFile(path.join(root, "deploy/monitoring/grafana/provisioning/dashboards/rwa.yml"), "utf8"));
  provider.providers[0].options.path = path.join(root, "deploy/monitoring/grafana/dashboards");
  await jsonFile(path.join(provisioning, "dashboards/rwa.yml"), provider);
  start("alertmanager", am, ["--config.file=" + path.join(run, "alertmanager.yml"),
    "--storage.path=" + path.join(run, "am-data"), "--web.listen-address=127.0.0.1:" + amPort, "--cluster.listen-address="]);
  start("prometheus", prom, ["--config.file=" + path.join(run, "prometheus.yml"),
    "--storage.tsdb.path=" + path.join(run, "prom-data"), "--web.listen-address=127.0.0.1:" + promPort]);
  start("grafana", grafana, ["server", "--homepath", grafanaHome], {
    GF_SERVER_HTTP_ADDR: "127.0.0.1", GF_SERVER_HTTP_PORT: String(grafanaPort),
    GF_PATHS_DATA: path.join(run, "grafana-data"), GF_PATHS_LOGS: path.join(run, "logs"),
    GF_PATHS_PLUGINS: path.join(run, "plugins"), GF_PATHS_PROVISIONING: provisioning,
    GF_SECURITY_ADMIN_PASSWORD: adminPassword, GF_AUTH_ANONYMOUS_ENABLED: "false",
    GF_USERS_ALLOW_SIGN_UP: "false", GF_ANALYTICS_REPORTING_ENABLED: "false",
    GF_ANALYTICS_CHECK_FOR_UPDATES: "false", GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES: "false",
    GF_PLUGINS_PREINSTALL_DISABLED: "true", GF_NEWS_NEWS_FEED_ENABLED: "false",
  });
  await waitFor("native services", async () => (await get(promURL + "/-/ready")).ok
    && (await get(amURL + "/-/ready")).ok && (await get(grafanaURL + "/api/health")).ok);
  record("native Prometheus / Alertmanager / Grafana startup");
  await waitFor("scraped metrics", async () => (await query(promURL, 'rwa_outbox_worker_ready{tenant="sandbox-monitoring"}'))[0]?.value[1] === "1");
  record("real Prometheus scrape of synthetic application exporter");
  await waitFor("dashboard provision", async () => (await get(grafanaURL + "/api/dashboards/uid/rwa-operations", { headers })).ok);
  const dashboard = await (await get(grafanaURL + "/api/dashboards/uid/rwa-operations", { headers })).json();
  assert.equal(dashboard.dashboard.panels.length, 26);
  assert.equal((await get(grafanaURL + "/api/dashboards/uid/rwa-operations")).status, 401);
  record("Grafana provisioned 26 panels; anonymous dashboard access denied");
  assert.equal((await get(grafanaURL + "/api/datasources/uid/rwa-prometheus/health", { headers })).status, 200);
  for (const panel of dashboard.dashboard.panels) for (const target of panel.targets ?? []) await query(promURL, target.expr);
  record("Grafana datasource healthy; every dashboard query parses in native Prometheus");
  if (process.env.RWA_PLAYWRIGHT_MODULE) {
    if (!path.isAbsolute(process.env.RWA_PLAYWRIGHT_MODULE)) throw new Error("absolute Playwright module path required");
    const { chromium } = createRequire(import.meta.url)(process.env.RWA_PLAYWRIGHT_MODULE);
    const browser = await chromium.launch({ executablePath: process.env.RWA_CHROME_BIN,
      headless: true });
    try {
      const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
      // Authentication is restricted to this disposable local Grafana instance.
      await context.route('**/*', route => {
        if (new URL(route.request().url()).origin !== grafanaURL) return route.abort();
        return route.continue({ headers: { ...route.request().headers(), ...headers } });
      });
      const page = await context.newPage();
      const pageErrors = []; page.on('pageerror', e => pageErrors.push(e.message));
      await page.goto(grafanaURL + '/d/rwa-operations?orgId=1&from=now-5m&to=now', { waitUntil:'domcontentloaded' });
      await page.getByText('Operational boundary', {exact:true}).waitFor({timeout:30000});
      await page.screenshot({path:path.join(run,'dashboard-top.png')});
      await page.getByText('Application filesystem available ratio', {exact:true}).scrollIntoViewIfNeeded();
      await page.screenshot({path:path.join(run,'dashboard-runtime.png')});
      assert.deepEqual(pageErrors, []);
      record('isolated Chromium rendered Grafana dashboard and runtime panels without page errors; screenshots retained');
    } finally { await browser.close(); }
  }
  ready = false;
  await waitFor("firing webhook", () => events.some((e) => e.status === "firing" && e.alerts.some((a) => a.name === selected.alert)), 45000);
  record("readiness failure -> Prometheus -> Alertmanager -> authenticated local webhook");
  ready = true;
  await waitFor("resolved webhook", () => events.some((e) => e.status === "resolved" && e.alerts.some((a) => a.name === selected.alert)), 45000);
  record("readiness recovery -> resolved notification");
  exporterAvailable = false;
  await waitFor("scrape outage", async () => (await query(promURL, 'up{job="rwa-outbox"}'))[0]?.value[1] === "0");
  exporterAvailable = true;
  await waitFor("scrape recovery", async () => (await query(promURL, 'up{job="rwa-outbox"}'))[0]?.value[1] === "1");
  record("503 exporter outage and scrape recovery observed by native Prometheus");
  report.notifications = events;
  report.status = "PASS";
  console.log("MONITORING_RUNTIME_ACCEPTANCE_OK");
  if (visualSeconds) {
    await jsonFile(path.join(run, "visual-login.json"), { url: grafanaURL, username: "admin", password: adminPassword });
    console.log("LOCAL_SYNTHETIC_VISUAL_REVIEW: " + path.join(run, "visual-login.json"));
    await delay(visualSeconds * 1000);
  }
} catch (error) {
  report.status = "FAIL"; report.error = String(error.message).replaceAll(adminPassword, "[REDACTED]").replaceAll(receiverToken, "[REDACTED]");
  console.error(report.error); process.exitCode = 1;
} finally {
  for (const { child } of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  await Promise.all(children.map(async ({ child }) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await Promise.race([once(child, "exit").catch(() => {}), delay(5000)]);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }));
  for (const server of servers) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
  // Erase the ephemeral receiver credential from the retained config.
  await jsonFile(path.join(run, "alertmanager.yml"), { redacted: true });
  if (visualSeconds) await jsonFile(path.join(run, "visual-login.json"), { redacted: true });
  report.completedAt = new Date().toISOString();
  await jsonFile(path.join(run, "report.json"), report);
  console.log("Report: " + path.join(run, "report.json"));
}
