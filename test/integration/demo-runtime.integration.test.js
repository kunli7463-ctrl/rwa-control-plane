import assert from "node:assert/strict";
import test from "node:test";
import { DemoRuntime } from "../../src/demo-runtime.js";
import { loadRuntimeConfig } from "../../src/runtime-config.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("PostgreSQL web runtime survives restart with verified seed and persistent key", { skip: !enabled }, async () => {
  const config = loadRuntimeConfig({
    STORAGE_MODE: "postgres",
    DATABASE_URL: process.env.DATABASE_URL,
    AUTH_MODE: "sandbox",
    ALLOW_LOCAL_DEV_KEY: "true",
    LOCAL_KEY_FILE: ".local/dev-encryption-key.json",
  }, { cwd: process.cwd() });

  const first = await DemoRuntime.create(config);
  try {
    const issuer = await first.view({ role: "issuer", actorRef: null });
    assert.equal(issuer.runtime.storageMode, "POSTGRESQL");
    assert.equal(issuer.reconciliation.assetRegisterMatched, true);
  } finally {
    await first.close();
  }

  const restarted = await DemoRuntime.create(config);
  try {
    assert.equal(restarted.bootstrapState, "VERIFIED_EXISTING");
    const broker = await restarted.view({ role: "broker", actorRef: null });
    assert.equal(broker.runtime.storageMode, "POSTGRESQL");
    assert.ok(Array.isArray(broker.transactions));
  } finally {
    await restarted.close();
  }
});
