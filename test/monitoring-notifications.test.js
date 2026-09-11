import assert from "node:assert/strict";
import test from "node:test";
import { buildAlertmanagerConfig } from "../src/monitoring-notifications.js";
import { buildPrometheusConfig } from "../src/monitoring-config.js";

test("notifications are opt-in and use explicit receiver identity and secret-file authentication", () => {
  const args = { tenantId: "tenant-a", environment: "production" };
  assert.equal(buildPrometheusConfig(args).alerting, undefined);
  assert.deepEqual(buildPrometheusConfig({ ...args, notifications: true }).alerting.alertmanagers[0].static_configs[0].targets, ["alertmanager:9093"]);
  assert.throws(() => buildPrometheusConfig({ ...args, notifications: "false" }), /boolean/);
  const config = buildAlertmanagerConfig({ webhookURL: "https://alerts.partner.com/rwa", allowedHost: "alerts.partner.com" });
  const webhook = config.receivers[0].webhook_configs[0];
  assert.equal(webhook.send_resolved, true);
  assert.equal(webhook.http_config.follow_redirects, false);
  assert.equal(webhook.http_config.authorization.credentials_file, "/run/secrets/rwa_alert_webhook_token");
  assert.equal(webhook.http_config.authorization.credentials, undefined);
});

test("notification configuration rejects insecure, unapproved and credential-bearing destinations", () => {
  for (const url of ["http://alerts.partner.com/rwa", "https://other.partner.com/rwa",
    "https://user:password@alerts.partner.com/rwa", "https://alerts.partner.com/rwa?token=x",
    "https://alerts.partner.com/rwa#secret", "https://alerts.partner.com:8443/rwa",
    "https://127.0.0.1/rwa", "https://localhost/rwa", "not-a-url"]) {
    assert.throws(() => buildAlertmanagerConfig({ webhookURL: url, allowedHost: "alerts.partner.com" }));
  }
});

