// Labels identify deployments; they are not an authorization boundary.
export function buildPrometheusConfig({ tenantId, environment, notifications = false }) {
  if (typeof notifications !== "boolean") throw new TypeError("notifications must be boolean");
  for (const [name, value] of Object.entries({ tenantId, environment })) {
    if (typeof value !== "string" || !/^[a-z][a-z0-9-]{0,62}$/.test(value)) {
      throw new TypeError(name + " must be an explicit bounded deployment identifier");
    }
  }
  if (environment === "production" && tenantId.startsWith("sandbox")) {
    throw new TypeError("production monitoring cannot identify a sandbox tenant");
  }
  return {
    global: { scrape_interval: "15s", evaluation_interval: "15s" },
    rule_files: ["/etc/prometheus/rwa-alerts.yml"],
    ...(notifications ? { alerting: { alertmanagers: [{ static_configs: [{ targets: ["alertmanager:9093"] }] }] } } : {}),
    scrape_configs: [
      ["outbox", 8770], ["prover", 8771], ["web", 8772],
    ].map(([worker, port]) => ({
      job_name: "rwa-" + worker,
      metrics_path: "/metrics/prometheus",
      scrape_timeout: "5s",
      static_configs: [{
        targets: [(worker === "web" ? "web" : worker + "-worker") + ":" + port],
        labels: { tenant: tenantId, environment },
      }],
    })),
  };
}
