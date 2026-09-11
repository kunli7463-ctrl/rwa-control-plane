import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PostgresStore, assertBalancedEntries, assertTransition, sha256Canonical } from "../src/storage/postgres-store.js";

test("canonical hash is stable across object key order", () => {
  assert.equal(sha256Canonical({ b: 2, a: 1 }), sha256Canonical({ a: 1, b: 2 }));
});

test("transaction state machine accepts intended transition and rejects skips", () => {
  assert.doesNotThrow(() => assertTransition("REQUESTED", "POLICY_CHECKED"));
  assert.doesNotThrow(() => assertTransition("POLICY_CHECKED", "PROOF_PENDING"));
  assert.doesNotThrow(() => assertTransition("PROOF_PENDING", "ROOT_PENDING"));
  assert.doesNotThrow(() => assertTransition("ROOT_PENDING", "SETTLED"));
  assert.throws(() => assertTransition("PROOF_PENDING", "SETTLED"), { code: "INVALID_STATE_TRANSITION" });
  assert.throws(() => assertTransition("REQUESTED", "SETTLED"), { code: "INVALID_STATE_TRANSITION" });
  assert.throws(() => assertTransition("SETTLED", "REQUESTED"), { code: "INVALID_STATE_TRANSITION" });
});

test("ledger validator requires non-zero, per-asset balance", () => {
  assert.doesNotThrow(() => assertBalancedEntries([
    { assetCode: "FUND-UNIT", signedDelta: "25" },
    { assetCode: "FUND-UNIT", signedDelta: "-25" },
  ]));
  assert.throws(() => assertBalancedEntries([
    { assetCode: "FUND-UNIT", signedDelta: "25" },
    { assetCode: "FUND-UNIT", signedDelta: "-24" },
  ]), { code: "UNBALANCED_LEDGER_BATCH" });
  assert.throws(() => assertBalancedEntries([
    { assetCode: "FUND-UNIT", signedDelta: "1" },
    { assetCode: "USD", signedDelta: "-1" },
  ]), { code: "UNBALANCED_LEDGER_BATCH" });
});

test("migration contains database-side integrity boundaries", async () => {
  const sql = await readFile(new URL("../db/migrations/001_production_core.sql", import.meta.url), "utf8");
  for (const required of [
    "row_version bigint NOT NULL DEFAULT 0",
    "assert_balanced_batch",
    "validate_ledger_entry",
    "posted ledger batch % is immutable",
    "reject_append_only_mutation",
    "enforce_maker_checker_separation",
    "audit_chain_single_successor",
    "UNIQUE (tenant_id, idempotency_key)",
    "FOR EACH ROW EXECUTE FUNCTION rwa.validate_ledger_entry()",
  ]) assert.match(sql, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("queue transaction uses read committed and always releases its client", async () => {
  const queries = [];
  let releases = 0;
  const client = {
    async query(sql) {
      queries.push(sql);
      return { rows: [] };
    },
    release() { releases += 1; },
  };
  const store = new PostgresStore({ async connect() { return client; } });
  const result = await store.withReadCommittedTransaction(async (transactionClient) => {
    assert.equal(transactionClient, client);
    await transactionClient.query("SELECT 1");
    return "ok";
  });
  assert.equal(result, "ok");
  assert.deepEqual(queries, ["BEGIN ISOLATION LEVEL READ COMMITTED", "SELECT 1", "COMMIT"]);
  assert.equal(releases, 1);
});

test("queue transaction rolls back and releases after failure", async () => {
  const queries = [];
  let releases = 0;
  const client = {
    async query(sql) { queries.push(sql); },
    release() { releases += 1; },
  };
  const store = new PostgresStore({ async connect() { return client; } });
  await assert.rejects(
    store.withReadCommittedTransaction(async () => { throw new Error("synthetic failure"); }),
    /synthetic failure/,
  );
  assert.deepEqual(queries, ["BEGIN ISOLATION LEVEL READ COMMITTED", "ROLLBACK"]);
  assert.equal(releases, 1);
});
