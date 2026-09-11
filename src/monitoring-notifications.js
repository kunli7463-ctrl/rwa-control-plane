import { isIP } from "node:net";

export function buildAlertmanagerConfig({ webhookURL, allowedHost }) {
  let url;
  try { url = new URL(webhookURL); } catch { throw new TypeError("an approved HTTPS webhook is required"); }
  if (url.protocol !== "https:" || !allowedHost || url.hostname !== allowedHost
      || url.username || url.password || url.search || url.hash
      || (url.port && url.port !== "443") || isIP(url.hostname.replace(/^\[|\]$/g, ""))
      || !url.hostname.includes(".") || /(^|\.)(localhost|local|invalid|test|example)$/.test(url.hostname)) {
    throw new TypeError("webhook must match the approved DNS host, use HTTPS and contain no embedded credentials");
  }
  return {
    global: { resolve_timeout: "5m" },
    route: { receiver: "approved-operations", group_by: ["tenant", "environment", "alertname"],
      group_wait: "30s", group_interval: "5m", repeat_interval: "4h" },
    receivers: [{ name: "approved-operations", webhook_configs: [{
      url: url.href, send_resolved: true,
      http_config: { follow_redirects: false,
        authorization: { type: "Bearer", credentials_file: "/run/secrets/rwa_alert_webhook_token" },
        tls_config: { min_version: "TLS12" } },
    }] }],
  };
}

