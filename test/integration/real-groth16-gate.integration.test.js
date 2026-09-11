import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadPinnedGroth16Adapter, sha256FileBytes } from "../../src/security/snarkjs-verifier.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ZkSettlementGate } from "../../src/storage/zk-settlement-gate.js";

const fixtureDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), "../fixtures/groth16-local-only",
);
const migrationsDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations",
);

function localDatabaseConfiguration() {
  if (!process.env.DATABASE_URL) return null;
  const applicationUrl = new URL(process.env.DATABASE_URL);
  if (!new Set(["127.0.0.1", "localhost", "::1"]).has(applicationUrl.hostname)) return null;
  const databaseName = `rwa_g16_${process.pid}_${Date.now()}`;
  const adminUrl = new URL(applicationUrl);
  adminUrl.username = "rwa_admin";
  adminUrl.pathname = "/postgres";
  const testUrl = new URL(applicationUrl);
  testUrl.pathname = `/${databaseName}`;
  return { databaseName, adminUrl: adminUrl.toString(), testUrl: testUrl.toString() };
}

async function jsonFixture(name) {
  return JSON.parse(await readFile(path.join(fixtureDirectory, name), "utf8"));
}

test("real Groth16 proof crosses the PostgreSQL authorization and acceptance gate atomically", {
  skip: !localDatabaseConfiguration(),
}, async () => {
  const configuration = localDatabaseConfiguration();
  const { Client } = await import("pg");
  const admin = new Client({ connectionString: configuration.adminUrl });
  let store;
  await admin.connect();
  try {
    assert.match(configuration.databaseName, /^rwa_g16_[0-9]+_[0-9]+$/);
    await admin.query(`CREATE DATABASE "${configuration.databaseName}" OWNER rwa_app`);
    store = await PostgresStore.connect({ connectionString: configuration.testUrl, max: 4 });
    await runMigrations(store.pool, { migrationsDir: migrationsDirectory });

    const manifestBytes = await readFile(path.join(fixtureDirectory, "manifest.json"));
    const [adapter, proof, publicSignals, inputs] = await Promise.all([
      loadPinnedGroth16Adapter({
        bundleDirectory: fixtureDirectory,
        expectedManifestFileHash: sha256FileBytes(manifestBytes),
      }),
      jsonFixture("valid_proof.json"),
      jsonFixture("public_signals.json"),
      jsonFixture("expected_public_inputs.json"),
    ]);
    const gate = new ZkSettlementGate(store, { proofAdapter: adapter });
    const tenantId = "real-groth16-tenant";
    const institutionId = "real-groth16-issuer";
    const productId = "real-groth16-product";
    const transactionId = "real-groth16-transfer";
    const requestHash = "a".repeat(64);

    await store.pool.query(
      "INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'Local Groth16 Test','HK','ACTIVE','test-only')",
      [institutionId],
    );
    await store.pool.query(
      "INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'Local Groth16 Test','HK',$2,'HKD','ACTIVE',1,'{}')",
      [productId, institutionId],
    );
    await store.pool.query(`INSERT INTO rwa.ledger_accounts
      (id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ($1,$2,$3,'real-groth16-owner',$4,'INVESTOR')`,
    [`ledger:${productId}:tenant-boundary`, tenantId, productId, `UNIT:${productId}`]);
    await store.pool.query(`INSERT INTO rwa.transaction_intents
      (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,
       rule_version,policy_snapshot_hash,private_payload_ciphertext,settlement_rail)
      VALUES ($1,$2,$3,$1,$4,'TRANSFER','PROOF_PENDING',1,$5,$6,'CONFIDENTIAL_NOTE')`,
    [transactionId, tenantId, productId, requestHash, "b".repeat(64), Buffer.from("encrypted")]);
    await store.pool.query(`INSERT INTO rwa.proof_circuit_versions
      (circuit_id,circuit_version,protocol,curve,verification_key_hash,artifact_manifest_hash,
       public_signal_order,status,activated_at)
      VALUES ($1,$2,'groth16','bn128',$3,$4,$5::jsonb,'ACTIVE',clock_timestamp())`,
    [adapter.manifest.circuitId, adapter.manifest.circuitVersion, adapter.verificationKeyHash,
      adapter.manifestHash, JSON.stringify(adapter.manifest.publicSignalOrder)]);
    await store.pool.query(`INSERT INTO rwa.zk_product_contexts
      (product_id,circuit_id,circuit_version,context_id,asset_type,created_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,'real-groth16-test')`,
    [productId, adapter.manifest.circuitId, adapter.manifest.circuitVersion,
      inputs.contextId, inputs.assetType]);
    await store.pool.query(`INSERT INTO rwa.zk_execution_instructions
      (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,'real-groth16-test')`,
    [transactionId, tenantId, requestHash, inputs.fee, inputs.recipient, inputs.relayer]);
    await store.pool.query(`INSERT INTO rwa.zk_merkle_roots
      (context_id,merkle_root,tree_size,status,observed_at,source_reference)
      VALUES ($1::numeric,$2::numeric,3,'CURRENT',clock_timestamp(),'real-groth16-test')`,
    [inputs.contextId, inputs.merkleRoot]);

    await gate.authorize({ transactionId, tenantId, proofPublicInputs: inputs });
    const relabelled = [...publicSignals];
    relabelled[5] = (BigInt(relabelled[5]) + 1n).toString();
    await assert.rejects(
      gate.accept({ transactionId, tenantId, proof, publicSignals: relabelled }),
      { code: "PROOF_CONTEXT_MISMATCH" },
    );
    const receipt = await gate.accept({ transactionId, tenantId, proof, publicSignals });
    assert.equal(receipt.verified, true);
    assert.equal(receipt.proofAccepted, true);
    assert.equal(receipt.settlementApplied, false);
    assert.equal(receipt.transactionState, "ROOT_PENDING");
    assert.equal(receipt.finalityDomain, "CONFIDENTIAL_PROOF_REGISTRY");
    assert.equal(receipt.legalRegisterApplied, false);
    await gate.proposeFinalization({
      transactionId, tenantId, outputMerkleRoot: "12345678901234567890", outputTreeSize: 5,
      rootSourceReference: "real-groth16-root-publication",
      executionReference: "real-groth16-effects", proposedBy: "real-groth16-maker",
    });
    const finalized = await gate.finalize({
      transactionId, tenantId, finalizedBy: "real-groth16-checker",
    });
    assert.equal(finalized.settlementApplied, true);
    assert.equal(finalized.finalityDomain, "CONFIDENTIAL_NOTE_LEDGER");

    const state = await store.pool.query(`SELECT
      (SELECT count(*)::int FROM rwa.zk_proof_receipts) receipts,
      (SELECT count(*)::int FROM rwa.zk_spent_nullifiers) nullifiers,
      (SELECT count(*)::int FROM rwa.zk_output_commitments) outputs,
      (SELECT count(*)::int FROM rwa.zk_settlements) settlements,
      (SELECT current_state FROM rwa.transaction_intents WHERE id=$1) transaction_state,
      (SELECT count(*)::int FROM rwa.audit_events WHERE event_type='zk.confidential_transfer.settled') audit_events,
      (SELECT count(*)::int FROM rwa.outbox_events WHERE topic='rwa.zk.confidential_transfer.settled') outbox_events`,
    [transactionId]);
    assert.deepEqual(state.rows[0], {
      receipts: 1, nullifiers: 2, outputs: 2, settlements: 1,
      transaction_state: "SETTLED", audit_events: 1, outbox_events: 1,
    });
  } finally {
    if (store) await store.close();
    await admin.query(`DROP DATABASE IF EXISTS "${configuration.databaseName}"`);
    await admin.end();
  }
});
