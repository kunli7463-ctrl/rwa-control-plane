#!/usr/bin/env node
// Operations CLI for the global audit chain (finding L3).
//
//   node scripts/audit-checkpoint.js create --by ops-operator
//   node scripts/audit-checkpoint.js verify
//   node scripts/audit-checkpoint.js anchor --checkpoint 7 --service notary.example --reference receipt-123
//
// `create` prints the digest to publish to an external anchor; `anchor` records
// where it was published; `verify` recomputes every checkpoint and exits 1 when
// the stored history no longer reproduces an anchored digest.
import { AuditChainCheckpointService } from "../src/storage/audit-checkpoint-service.js";
import { PostgresStore } from "../src/storage/postgres-store.js";

const [command, ...rest] = process.argv.slice(2);
const options = new Map();
for (let index = 0; index < rest.length; index += 2) options.set(rest[index].replace(/^--/, ""), rest[index + 1]);

// Only the tenant scope and the database are needed; no runtime keys are loaded.
const tenantId = process.env.TENANT_ID ?? "sandbox-hk";
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required");
  process.exit(2);
}
const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 2 });
const service = new AuditChainCheckpointService(store, { tenantId });
try {
  if (command === "create") {
    console.log(JSON.stringify(await service.createCheckpoint({ createdBy: options.get("by") ?? "audit-checkpoint-cli" }), null, 2));
  } else if (command === "verify") {
    const result = await service.verifyCheckpoints();
    console.log(JSON.stringify(result, null, 2));
    if (!result.valid) process.exitCode = 1;
  } else if (command === "anchor") {
    console.log(JSON.stringify(await service.recordExternalAnchor({
      checkpointNumber: Number(options.get("checkpoint")),
      anchor: { service: options.get("service"), reference: options.get("reference") },
    }), null, 2));
  } else {
    console.error("usage: audit-checkpoint.js create|verify|anchor [--by ref] [--checkpoint n --service s --reference r]");
    process.exitCode = 2;
  }
} catch (error) {
  console.error(JSON.stringify({ error: error.code ?? "AUDIT_CHECKPOINT_FAILED", message: error.message }));
  process.exitCode = 1;
} finally {
  await store.close();
}
