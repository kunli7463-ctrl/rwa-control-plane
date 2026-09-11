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
const payloadCipher = new AesGcmEnvelopeCipher(new LocalKeyring({
  activeKeyId: "liveness-v1", keys: { "liveness-v1": randomBytes(32) },
}));

async function authorizedTransfer(store, label) {
  const suffix = `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `liveness-tenant-${suffix}`;
  const issuerId = `liveness-issuer-${suffix}`;
  const productId = `liveness-product-${suffix}`;
  const transactionId = `liveness-transaction-${suffix}`;
  const circuitId = `liveness-joinsplit-${suffix}`;
  const circuitVersion = "1.0.0-test";
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
  await store.pool.query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'Liveness','HK','ACTIVE','test')", [issuerId]);
  await store.pool.query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'Liveness','HK',$2,'HKD','ACTIVE',1,'{}')", [productId, issuerId]);
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
    (context_id,merkle_root,tree_size,status,observed_at,expires_at,source_reference)
    VALUES ($1::numeric,$2::numeric,2,'HISTORICAL',clock_timestamp(),clock_timestamp()+interval '1 day','test')`,
  [inputs.contextId, inputs.merkleRoot]);
  await gate.authorize({ transactionId, tenantId, proofPublicInputs: inputs });
  return { tenantId, transactionId, gate, signals: JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => inputs[name]), suffix };
}

async function makeDue(store, transactionId) {
  await store.pool.query("UPDATE rwa.prover_jobs SET next_attempt_at=clock_timestamp() WHERE transaction_id=$1", [transactionId]);
}

test("a long-running remote proof survives many polls and a transient error", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  await runMigrations(store.pool, { migrationsDir });
  try {
    const transfer = await authorizedTransfer(store, "long");
    let polls = 0;
    const proverClient = {
      async submitJob() { return { jobId: `remote-${transfer.suffix}`, state: "QUEUED" }; },
      async getJob(jobId) {
        polls += 1;
        if (polls <= 40) return { jobId, state: "RUNNING" };
        if (polls === 41) throw Object.assign(new Error("transient prover gateway reset"), { code: "PROVER_SERVICE_UNAVAILABLE" });
        return { jobId, state: "SUCCEEDED", proof: { test: true }, publicSignals: transfer.signals };
      },
    };
    const service = new ProverJobService(store, {
      proverClient, payloadCipher, zkSettlementGate: transfer.gate, tenantId: transfer.tenantId, logger: { error() {} },
    });
    await service.request({ transactionId: transfer.transactionId, tenantId: transfer.tenantId,
      witnessReference: "vault://rwa/witness/long", requestedBy: "broker-test" });
    assert.equal((await service.runOnce({ workerId: "worker-long" })).state, "REMOTE_PENDING");
    for (let poll = 1; poll <= 40; poll += 1) {
      await makeDue(store, transfer.transactionId);
      const pending = await service.runOnce({ workerId: "worker-long" });
      assert.equal(pending.state, "REMOTE_PENDING", `poll ${poll}`);
      assert.equal(pending.attempts, 0, "status polls are not failure attempts");
    }
    await makeDue(store, transfer.transactionId);
    const retryable = await service.runOnce({ workerId: "worker-long" });
    assert.equal(retryable.state, "RETRYABLE");
    assert.equal(retryable.attempts, 1);
    // RETRYABLE rows are immutable except through their lifecycle, so wait out the 2s backoff.
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    const verified = await service.runOnce({ workerId: "worker-long" });
    assert.equal(verified.state, "VERIFIED");
    const row = await store.pool.query("SELECT attempts,poll_count FROM rwa.prover_jobs WHERE transaction_id=$1", [transfer.transactionId]);
    assert.equal(row.rows[0].attempts, 1);
    assert.equal(row.rows[0].poll_count, 42);
  } finally {
    await store.close();
  }
});

test("a job abandoned mid-submission by a crashed worker is recovered after its lease expires", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  await runMigrations(store.pool, { migrationsDir });
  try {
    const transfer = await authorizedTransfer(store, "crash");
    let releaseHungSubmission;
    const hung = new Promise((resolve) => { releaseHungSubmission = resolve; });
    const submissions = [];
    const crashingClient = {
      async submitJob(request) { submissions.push(request.requestId); await hung; return { jobId: "never-recorded", state: "QUEUED" }; },
      async getJob() { throw new Error("unused"); },
    };
    const healthyClient = {
      async submitJob(request) { submissions.push(request.requestId); return { jobId: `remote-${transfer.suffix}`, state: "QUEUED" }; },
      async getJob() { throw new Error("unused"); },
    };
    const options = { payloadCipher, zkSettlementGate: transfer.gate, tenantId: transfer.tenantId, logger: { error() {} } };
    const crashing = new ProverJobService(store, { ...options, proverClient: crashingClient, leaseMs: 50 });
    const healthy = new ProverJobService(store, { ...options, proverClient: healthyClient });
    await healthy.request({ transactionId: transfer.transactionId, tenantId: transfer.tenantId,
      witnessReference: "vault://rwa/witness/crash", requestedBy: "broker-test" });
    const abandoned = crashing.runOnce({ workerId: "worker-crashed" }).catch((error) => error);
    for (let wait = 0; wait < 50 && submissions.length === 0; wait += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(submissions.length, 1);
    await new Promise((resolve) => setTimeout(resolve, 120));
    const resubmitted = await healthy.runOnce({ workerId: "worker-healthy" });
    assert.equal(resubmitted?.state, "REMOTE_PENDING");
    assert.equal(resubmitted.attempts, 1, "the abandoned attempt counts as one failure");
    assert.deepEqual(submissions, [submissions[0], submissions[0]], "resubmission reuses the idempotent request id");
    releaseHungSubmission();
    const late = await abandoned;
    assert.ok(late instanceof Error, "the crashed worker cannot overwrite the recovered job");
    const row = await store.pool.query("SELECT state,external_job_id FROM rwa.prover_jobs WHERE transaction_id=$1", [transfer.transactionId]);
    assert.deepEqual(row.rows[0], { state: "REMOTE_PENDING", external_job_id: `remote-${transfer.suffix}` });
  } finally {
    await store.close();
  }
});
