import { writeFile } from "node:fs/promises";
import { buildPrometheusConfig } from "../src/monitoring-config.js";

const [output] = process.argv.slice(2);
if (!output || process.argv.length !== 3) throw new Error("Usage: node scripts/build-monitoring-config.js OUTPUT.yml");
if (![undefined, "true", "false"].includes(process.env.RWA_ENABLE_NOTIFICATIONS)) {
  throw new Error("RWA_ENABLE_NOTIFICATIONS must be exactly true or false when set");
}
const config = buildPrometheusConfig({
  tenantId: process.env.TENANT_ID,
  environment: process.env.RWA_MONITORING_ENVIRONMENT,
  notifications: process.env.RWA_ENABLE_NOTIFICATIONS === "true",
});
// JSON is valid YAML. Exclusive creation prevents overwriting an approved config.
await writeFile(output, JSON.stringify(config, null, 2) + "\n", { flag: "wx", mode: 0o600 });
console.log("MONITORING_CONFIG_CREATED; notification delivery is not configured by this command");
