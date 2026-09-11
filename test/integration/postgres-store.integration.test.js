import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("PostgreSQL posts only balanced, asset-consistent ledger batches", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });

  const client = await pool.connect();
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    await client.query("BEGIN");
    const issuer = `test-issuer-${suffix}`;
    const product = `test-product-${suffix}`;
    const transaction = `test-transaction-${suffix}`;
    const left = `test-left-${suffix}`;
    const right = `test-right-${suffix}`;
    await client.query(
      "INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'Test','HK','ACTIVE','test')",
      [issuer],
    );
    await client.query(
      `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules)
       VALUES ($1,'Test','HK',$2,'HKD','ACTIVE',1,'{}')`,
      [product, issuer],
    );
    await client.query(
      `INSERT INTO rwa.transaction_intents
       (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,rule_version,
        policy_snapshot_hash,private_payload_ciphertext)
       VALUES ($1,'test',$2,$3,$4,'TRANSFER','REGISTER_PENDING',1,$5,$6)`,
      [transaction, product, `idem-${suffix}`, "a".repeat(64), "b".repeat(64), Buffer.from("ciphertext")],
    );
    for (const [id, owner] of [[left, "left"], [right, "right"]]) {
      await client.query(
        `INSERT INTO rwa.ledger_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
         VALUES ($1,'test',$2,$3,'FUND-UNIT','INVESTOR')`,
        [id, product, owner],
      );
    }
    await store.appendLedgerBatch(client, {
      batchId: `test-batch-${suffix}`,
      transactionId: transaction,
      entries: [
        { accountId: left, assetCode: "FUND-UNIT", signedDelta: "-100" },
        { accountId: right, assetCode: "FUND-UNIT", signedDelta: "100" },
      ],
    });
    const posted = await client.query("SELECT status,posted_at FROM rwa.ledger_batches WHERE transaction_id=$1", [transaction]);
    assert.equal(posted.rows[0].status, "POSTED");
    assert.ok(posted.rows[0].posted_at);
    await assert.rejects(
      client.query("UPDATE rwa.ledger_batches SET status='DRAFT' WHERE transaction_id=$1", [transaction]),
      /immutable/,
    );
    await client.query("ROLLBACK");
  } finally {
    await client.query("ROLLBACK").catch(() => {});
    client.release();
    await pool.end();
  }
});
