import { writeFile } from "node:fs/promises";
import { buildAlertmanagerConfig } from "../src/monitoring-notifications.js";
const [output] = process.argv.slice(2);
if (!output || process.argv.length !== 3) throw new Error("Usage: node scripts/build-notification-config.js OUTPUT.yml");
const config = buildAlertmanagerConfig({
  webhookURL: process.env.RWA_ALERT_WEBHOOK_URL,
  allowedHost: process.env.RWA_ALERT_WEBHOOK_ALLOWED_HOST,
});
await writeFile(output, JSON.stringify(config, null, 2) + "\n", { flag: "wx", mode: 0o600 });
console.log("NOTIFICATION_CONFIG_CREATED; no notification sent");

