import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { appendMerkleLeaves, emptyMerkleTreeState, merkleLeaf } from "../../src/security/poseidon-merkle.js";
import { Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, verificationKeyHash } from "../../src/security/proof-adapter.js";
import { grantRuntimePrivileges, verifyRuntimeDatabasePrivileges } from "../../src/storage/database-privileges.js";
import { runMigrations, verifyMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ZkSettlementGate } from "../../src/storage/zk-settlement-gate.js";

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");

function localConfiguration() {
  if (!process.env.DATABASE_URL) return null;
  const applicationUrl = new URL(process.env.DATABASE_URL);
  if (!new Set(["127.0.0.1", "localhost", "::1"]).has(applicationUrl.hostname)) return null;
  const token = `${process.pid}_${Date.now()}`;
  const adminUrl = new URL(applicationUrl);
  adminUrl.username = "rwa_admin";
  adminUrl.pathname = "/postgres";
  const database = `rwa_priv_${token}`;
  const url = (user) => {
    const value = new URL(applicationUrl);
    value.username = user;
    value.pathname = `/${database}`;
    return value.toString();
  };
  return {
    adminUrl: adminUrl.toString(), database,
    migrator: `rwa_mig_${token}`, runtime: `rwa_rt_${token}`, url,
  };
}

test("production runtime role cannot bypass append-only guards but can settle confidential transfers", {
  skip: !localConfiguration(),
}, async () => {
  const configuration = localConfiguration();
  const { Client } = await import("pg");
  const admin = new Client({ connectionString: configuration.adminUrl });
  await admin.connect();
  let migrator;
  let runtime;
  try {
    await admin.query(`CREATE ROLE "${configuration.migrator}" LOGIN`);
    await admin.query(`CREATE ROLE "${configuration.runtime}" LOGIN`);
    await admin.query(`CREATE DATABASE "${configuration.database}" OWNER "${configuration.migrator}"`);
    migrator = await PostgresStore.connect({ connectionString: configuration.url(configuration.migrator), max: 2 });
    await runMigrations(migrator.pool, { migrationsDir });

    await assert.rejects(grantRuntimePrivileges(migrator.pool, { runtimeRole: configuration.migrator }),
      { code: "RUNTIME_DATABASE_ROLE_TOO_PRIVILEGED" });
    await assert.rejects(grantRuntimePrivileges(migrator.pool, { runtimeRole: "Robert'); DROP" }),
      { code: "INVALID_RUNTIME_DATABASE_ROLE" });
    const migratorCheck = await verifyRuntimeDatabasePrivileges(migrator.pool).catch((error) => error);
    assert.equal(migratorCheck.code, "DATABASE_RUNTIME_ROLE_TOO_PRIVILEGED");
    assert.ok(migratorCheck.details.violations.includes("SCHEMA_OWNER"));

    await grantRuntimePrivileges(migrator.pool, { runtimeRole: configuration.runtime });
    runtime = await PostgresStore.connect({ connectionString: configuration.url(configuration.runtime), max: 4 });
    assert.deepEqual(await verifyRuntimeDatabasePrivileges(runtime.pool),
      { role: configuration.runtime, leastPrivilege: true });
    assert.equal((await verifyMigrations(runtime.pool, { migrationsDir })).current, true);

    // A full confidential settlement as the least-privilege runtime role.
    const suffix = `${Date.now()}`;
    const verificationKey = { protocol: "groth16", curve: "bn128", id: suffix };
    const manifest = { protocol: "groth16", curve: "bn128", circuitId: `priv-${suffix}`, circuitVersion: "1.0.0-test",
      publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER] };
    const adapter = new Groth16JoinSplitProofAdapter({ verifier: { verify: async () => true }, verificationKey, manifest,
      expectedVerificationKeyHash: verificationKeyHash(verificationKey) });
    const gate = new ZkSettlementGate(runtime, { proofAdapter: adapter });
    const tenantId = "priv-tenant";
    const productId = "priv-product";
    const transactionId = "priv-transfer";
    const inputs = Object.fromEntries(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(1000 + index)]));
    const query = (sql, parameters) => runtime.pool.query(sql, parameters);
    await query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ('priv-issuer','P','HK','ACTIVE','test')");
    await query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'P','HK','priv-issuer','HKD','ACTIVE',1,'{}')", [productId]);
    await query(`INSERT INTO rwa.ledger_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ('priv-ledger',$1,$2,'owner',$3,'INVESTOR')`, [tenantId, productId, `UNIT:${productId}`]);
    await query(`INSERT INTO rwa.transaction_intents
      (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,rule_version,
       policy_snapshot_hash,private_payload_ciphertext,settlement_rail)
      VALUES ($1,$2,$3,$1,$4,'TRANSFER','PROOF_PENDING',1,$5,$6,'CONFIDENTIAL_NOTE')`,
    [transactionId, tenantId, productId, "a".repeat(64), "b".repeat(64), Buffer.from("encrypted")]);
    await query(`INSERT INTO rwa.proof_circuit_versions
      (circuit_id,circuit_version,protocol,curve,verification_key_hash,artifact_manifest_hash,public_signal_order,status,activated_at)
      VALUES ($1,$2,'groth16','bn128',$3,$4,$5::jsonb,'ACTIVE',clock_timestamp())`,
    [manifest.circuitId, manifest.circuitVersion, adapter.verificationKeyHash, adapter.manifestHash, JSON.stringify(manifest.publicSignalOrder)]);
    await query(`INSERT INTO rwa.zk_product_contexts(product_id,circuit_id,circuit_version,context_id,asset_type,created_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,'test')`,
    [productId, manifest.circuitId, manifest.circuitVersion, inputs.contextId, inputs.assetType]);
    await query(`INSERT INTO rwa.zk_execution_instructions(transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,'test')`,
    [transactionId, tenantId, "a".repeat(64), inputs.fee, inputs.recipient, inputs.relayer]);
    const genesis = emptyMerkleTreeState();
    inputs.merkleRoot = genesis.root;
    await query(`INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,frontier,status,observed_at,source_reference)
      VALUES ($1::numeric,$2::numeric,0,$3::jsonb,'CURRENT',clock_timestamp(),'genesis')`,
    [inputs.contextId, genesis.root, JSON.stringify(genesis.frontier)]);
    await gate.authorize({ transactionId, tenantId, proofPublicInputs: inputs });
    await gate.accept({ transactionId, tenantId, proof: { test: true },
      publicSignals: JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => inputs[name]) });
    const next = appendMerkleLeaves(genesis, [
      merkleLeaf(inputs.outputCommitmentX0, inputs.outputCommitmentY0).toString(),
      merkleLeaf(inputs.outputCommitmentX1, inputs.outputCommitmentY1).toString(),
    ]);
    await gate.proposeFinalization({ transactionId, tenantId, outputMerkleRoot: next.root, outputTreeSize: 2,
      rootSourceReference: "publication", executionReference: "execution", proposedBy: "maker" });
    const settled = await gate.finalize({ transactionId, tenantId, finalizedBy: "checker" });
    assert.equal(settled.state, "SETTLED");
    const [claimed] = await runtime.claimOutboxBatch({ workerId: "priv-worker", tenantId, limit: 1 });
    await runtime.markOutboxPublished({ id: claimed.id, workerId: "priv-worker" });

    // The runtime identity cannot remove the double-spend guard.
    for (const statement of [
      "ALTER TABLE rwa.zk_spent_nullifiers DISABLE TRIGGER USER",
      "DROP TRIGGER zk_spent_nullifiers_append_only_guard ON rwa.zk_spent_nullifiers",
      "TRUNCATE rwa.zk_spent_nullifiers",
      "DELETE FROM rwa.zk_spent_nullifiers",
      "DELETE FROM rwa.audit_events",
      "CREATE TABLE rwa.shadow_nullifiers(id int)",
    ]) {
      await assert.rejects(query(statement), { code: /^(42501|42P01)$/ }, statement);
    }
    const nullifiers = await query("SELECT count(*)::int AS count FROM rwa.zk_spent_nullifiers");
    assert.equal(nullifiers.rows[0].count, 2);
  } finally {
    if (runtime) await runtime.close();
    if (migrator) await migrator.close();
    await admin.query(`DROP DATABASE IF EXISTS "${configuration.database}"`);
    await admin.query(`DROP ROLE IF EXISTS "${configuration.runtime}"`);
    await admin.query(`DROP ROLE IF EXISTS "${configuration.migrator}"`);
    await admin.end();
  }
});
