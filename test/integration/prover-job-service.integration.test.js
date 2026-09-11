import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AesGcmEnvelopeCipher, LocalKeyring } from "../../src/security/envelope-crypto.js";
import { Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, verificationKeyHash } from "../../src/security/proof-adapter.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ProverJobService } from "../../src/storage/prover-job-service.js";
import { ZkSettlementGate } from "../../src/storage/zk-settlement-gate.js";

const enabled = Boolean(process.env.DATABASE_URL);
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");

test("durable isolated prover job advances an authorized transfer through the verified ZK gate", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  await runMigrations(store.pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `prover-tenant-${suffix}`;
  const issuerId = `prover-issuer-${suffix}`;
  const productId = `prover-product-${suffix}`;
  const transactionId = `prover-transaction-${suffix}`;
  const circuitId = `prover-joinsplit-${suffix}`;
  const circuitVersion = "3.0.0-test";
  const verificationKey = { protocol: "groth16", curve: "bn128", id: suffix };
  const manifest = { protocol: "groth16", curve: "bn128", circuitId, circuitVersion,
    publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER] };
  const adapter = new Groth16JoinSplitProofAdapter({
    verifier: { verify: async () => true }, verificationKey, manifest,
    expectedVerificationKeyHash: verificationKeyHash(verificationKey),
  });
  const gate = new ZkSettlementGate(store, { proofAdapter: adapter });
  const domain = BigInt(Date.now()) * 1_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));
  const inputs = Object.fromEntries(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(index + 1)]));
  Object.assign(inputs, {
    merkleRoot: domain.toString(), contextId: (domain + 1n).toString(),
    inputNullifier0: (domain + 2n).toString(), inputNullifier1: (domain + 3n).toString(),
    outputCommitmentX0: (domain + 4n).toString(), outputCommitmentX1: (domain + 5n).toString(),
    outputCommitmentY0: (domain + 6n).toString(), outputCommitmentY1: (domain + 7n).toString(),
  });
  const signals = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => inputs[name]);
  const remoteCalls = [];
  const proverClient = {
    async submitJob(request) {
      remoteCalls.push(request);
      return { jobId: `remote-${suffix}`, state: "QUEUED" };
    },
    async getJob(jobId) {
      return { jobId, state: "SUCCEEDED", proof: { test: true }, publicSignals: signals };
    },
  };
  const payloadCipher = new AesGcmEnvelopeCipher(new LocalKeyring({
    activeKeyId: "test-v1", keys: { "test-v1": randomBytes(32) },
  }));
  const service = new ProverJobService(store, { proverClient, payloadCipher, zkSettlementGate: gate, tenantId });
  try {
    await store.pool.query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'Prover Test','HK','ACTIVE','test')", [issuerId]);
    await store.pool.query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'Prover Test','HK',$2,'HKD','ACTIVE',1,'{}')", [productId, issuerId]);
    await store.pool.query(`INSERT INTO rwa.ledger_accounts
      (id,tenant_id,product_id,owner_ref,asset_code,account_type) VALUES ($1,$2,$3,'owner',$4,'INVESTOR')`,
    [`ledger:${productId}:boundary`, tenantId, productId, `UNIT:${productId}`]);
    await store.pool.query(`INSERT INTO rwa.transaction_intents
      (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,rule_version,
       policy_snapshot_hash,private_payload_ciphertext,settlement_rail)
      VALUES ($1,$2,$3,$1,$4,'TRANSFER','PROOF_PENDING',1,$5,$6,'CONFIDENTIAL_NOTE')`,
    [transactionId, tenantId, productId, "a".repeat(64), "b".repeat(64), Buffer.from("encrypted")]);
    await store.pool.query(`INSERT INTO rwa.proof_circuit_versions
      (circuit_id,circuit_version,protocol,curve,verification_key_hash,artifact_manifest_hash,
       public_signal_order,status,activated_at)
      VALUES ($1,$2,'groth16','bn128',$3,$4,$5::jsonb,'ACTIVE',clock_timestamp())`,
    [circuitId, circuitVersion, adapter.verificationKeyHash, adapter.manifestHash, JSON.stringify(manifest.publicSignalOrder)]);
    await store.pool.query(`INSERT INTO rwa.zk_product_contexts
      (product_id,circuit_id,circuit_version,context_id,asset_type,created_by) VALUES ($1,$2,$3,$4::numeric,$5::numeric,'test')`,
    [productId, circuitId, circuitVersion, inputs.contextId, inputs.assetType]);
    await store.pool.query(`INSERT INTO rwa.zk_execution_instructions
      (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,'test')`,
    [transactionId, tenantId, "a".repeat(64), inputs.fee, inputs.recipient, inputs.relayer]);
    await store.pool.query(`INSERT INTO rwa.zk_merkle_roots
      (context_id,merkle_root,tree_size,status,observed_at,source_reference)
      VALUES ($1::numeric,$2::numeric,2,'CURRENT',clock_timestamp(),'test')`,
    [inputs.contextId, inputs.merkleRoot]);
    await gate.authorize({ transactionId, tenantId, proofPublicInputs: inputs });

    const requested = await service.request({
      transactionId, tenantId, witnessReference: `vault://rwa/witness/${suffix}`, requestedBy: "broker-test",
    });
    assert.equal(requested.state, "QUEUED");
    assert.equal((await service.request({ transactionId, tenantId,
      witnessReference: `vault://rwa/witness/${suffix}`, requestedBy: "broker-test" })).created, false);
    const stored = await store.pool.query("SELECT witness_reference_ciphertext FROM rwa.prover_jobs WHERE id=$1", [requested.jobId]);
    assert.equal(stored.rows[0].witness_reference_ciphertext.includes(Buffer.from("vault://")), false);

    assert.equal((await service.runOnce({ workerId: "worker-test" })).state, "REMOTE_PENDING");
    assert.equal(remoteCalls.length, 1);
    assert.equal(remoteCalls[0].authorizationHash.length, 64);
    await store.pool.query("UPDATE rwa.prover_jobs SET next_attempt_at=clock_timestamp() WHERE id=$1", [requested.jobId]);
    const completed = await service.runOnce({ workerId: "worker-test" });
    assert.equal(completed.state, "VERIFIED");
    assert.ok(completed.proofReceiptId);
    const state = await store.pool.query(`SELECT
      (SELECT current_state FROM rwa.transaction_intents WHERE id=$1) transaction_state,
      (SELECT count(*)::int FROM rwa.zk_spent_nullifiers n JOIN rwa.zk_proof_receipts r ON r.id=n.proof_receipt_id WHERE r.transaction_id=$1) nullifiers,
      (SELECT count(*)::int FROM rwa.zk_output_commitments o JOIN rwa.zk_proof_receipts r ON r.id=o.proof_receipt_id WHERE r.transaction_id=$1) outputs`,
    [transactionId]);
    assert.deepEqual(state.rows[0], { transaction_state: "ROOT_PENDING", nullifiers: 2, outputs: 2 });
  } finally {
    await store.close();
  }
});
