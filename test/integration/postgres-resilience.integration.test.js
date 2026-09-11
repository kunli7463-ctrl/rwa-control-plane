import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("serializable retries preserve every concurrent product version increment", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 12 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const issuerId = `resilience-issuer-${suffix}`;
  const productId = `resilience-product-${suffix}`;
  try {
    await store.pool.query(
      `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem)
       VALUES ($1,'Resilience Issuer','HK','ACTIVE','test')`,
      [issuerId],
    );
    await store.pool.query(
      `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules)
       VALUES ($1,'Resilience Product','HK',$2,'HKD','ACTIVE',1,'{}')`,
      [productId, issuerId],
    );
    const attempts = new Map();
    const concurrency = 10;
    await Promise.all(Array.from({ length: concurrency }, (_, index) => (
      store.withSerializableTransaction(async (client) => {
        attempts.set(index, (attempts.get(index) ?? 0) + 1);
        const current = await client.query("SELECT row_version FROM rwa.products WHERE id=$1", [productId]);
        await client.query("SELECT pg_sleep(0.003)");
        await client.query(
          "UPDATE rwa.products SET row_version=$2,updated_at=clock_timestamp() WHERE id=$1",
          [productId, Number(current.rows[0].row_version) + 1],
        );
      }, { retries: 20 })
    )));
    const final = await store.pool.query("SELECT row_version FROM rwa.products WHERE id=$1", [productId]);
    assert.equal(Number(final.rows[0].row_version), concurrency);
    assert.ok([...attempts.values()].some((count) => count > 1), "test must exercise a real serialization retry");
  } finally {
    await store.close();
  }
});

test("connection pool replaces a terminated backend without replaying the failed operation", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
  const victim = await pool.connect();
  let victimReleased = false;
  try {
    const pid = Number((await victim.query("SELECT pg_backend_pid() AS pid")).rows[0].pid);
    const killer = await pool.connect();
    try {
      assert.equal((await killer.query("SELECT pg_terminate_backend($1) AS terminated", [pid])).rows[0].terminated, true);
    } finally {
      killer.release();
    }
    await assert.rejects(victim.query("SELECT 1"));
    victim.release(true);
    victimReleased = true;
    assert.equal((await pool.query("SELECT 1 AS recovered")).rows[0].recovered, 1);
  } finally {
    if (!victimReleased) victim.release(true);
    await pool.end();
  }
});
