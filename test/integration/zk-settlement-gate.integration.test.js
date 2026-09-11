import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { BN254_SCALAR_FIELD, Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, verificationKeyHash } from "../../src/security/proof-adapter.js";
import { RedactedPayloadCipher } from "../../src/security/envelope-crypto.js";
import { ConfidentialTransferService } from "../../src/storage/confidential-transfer-service.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ZkSettlementGate } from "../../src/storage/zk-settlement-gate.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("ZK gate atomically records proof state and rejects nullifier replay", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const verificationKey = { protocol: "groth16", curve: "bn128", test: suffix };
  const manifest = { protocol: "groth16", curve: "bn128", circuitId: `joinsplit-${suffix}`,
    circuitVersion: "2.0.0-test", publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER] };
  const adapter = new Groth16JoinSplitProofAdapter({ verifier: { verify: async () => true }, verificationKey,
    manifest, expectedVerificationKeyHash: verificationKeyHash(verificationKey) });
  const gate = new ZkSettlementGate(store, { proofAdapter: adapter });
  const tenantId = `zk-tenant-${suffix}`;
  const issuerId = `zk-issuer-${suffix}`;
  const productId = `zk-product-${suffix}`;
  const expectedPublicInputs = Object.fromEntries(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(index + 1)]));
  const runDomain = BigInt(Date.now()) * 1_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));
  expectedPublicInputs.merkleRoot = runDomain.toString();
  expectedPublicInputs.contextId = (runDomain + 1n).toString();
  expectedPublicInputs.outputCommitmentX0 = (runDomain + 2n).toString();
  expectedPublicInputs.outputCommitmentX1 = (runDomain + 3n).toString();
  expectedPublicInputs.outputCommitmentY0 = (runDomain + 4n).toString();
  expectedPublicInputs.outputCommitmentY1 = (runDomain + 5n).toString();
  const publicSignals = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => expectedPublicInputs[name]);
  try {
    await store.pool.query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'ZK','HK','ACTIVE','test')", [issuerId]);
    await store.pool.query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'ZK','HK',$2,'HKD','ACTIVE',1,'{}')", [productId, issuerId]);
    await store.pool.query(`INSERT INTO rwa.ledger_accounts
      (id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ($1,$2,$3,'zk-owner',$4,'INVESTOR')`,
    [`ledger:${productId}:tenant-boundary`, tenantId, productId, `UNIT:${productId}`]);
    for (const transactionId of [`zk-tx-1-${suffix}`, `zk-tx-2-${suffix}`, `zk-tx-bad-${suffix}`]) {
      await store.pool.query(`INSERT INTO rwa.transaction_intents
        (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,rule_version,
         policy_snapshot_hash,private_payload_ciphertext,settlement_rail)
        VALUES ($1,$2,$3,$1,$4,'TRANSFER','PROOF_PENDING',1,$5,$6,'CONFIDENTIAL_NOTE')`,
      [transactionId, tenantId, productId, "a".repeat(64), "b".repeat(64), Buffer.from("encrypted")]);
    }
    await store.pool.query(`INSERT INTO rwa.proof_circuit_versions
      (circuit_id,circuit_version,protocol,curve,verification_key_hash,artifact_manifest_hash,public_signal_order,status,activated_at)
      VALUES ($1,$2,'groth16','bn128',$3,$4,$5::jsonb,'ACTIVE',clock_timestamp())`,
    [manifest.circuitId, manifest.circuitVersion, adapter.verificationKeyHash, adapter.manifestHash, JSON.stringify(manifest.publicSignalOrder)]);
    await store.pool.query(`INSERT INTO rwa.zk_product_contexts
      (product_id,circuit_id,circuit_version,context_id,asset_type,created_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,'integration-policy')`,
    [productId, manifest.circuitId, manifest.circuitVersion,
      expectedPublicInputs.contextId, expectedPublicInputs.assetType]);
    for (const transactionId of [`zk-tx-1-${suffix}`, `zk-tx-2-${suffix}`]) {
      await store.pool.query(`INSERT INTO rwa.zk_execution_instructions
        (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
        VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,'integration-authorizer')`,
      [transactionId, tenantId, "a".repeat(64), expectedPublicInputs.fee,
        expectedPublicInputs.recipient, expectedPublicInputs.relayer]);
    }
    await store.pool.query(`INSERT INTO rwa.zk_execution_instructions
      (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
      VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,'integration-authorizer')`,
    [`zk-tx-bad-${suffix}`, tenantId, "c".repeat(64), expectedPublicInputs.fee,
      expectedPublicInputs.recipient, expectedPublicInputs.relayer]);
    await store.pool.query(`INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,status,observed_at,source_reference)
      VALUES ($1::numeric,$2::numeric,2,'CURRENT',clock_timestamp(),'integration-test')`,
    [expectedPublicInputs.contextId, expectedPublicInputs.merkleRoot]);
    const preparation = new ConfidentialTransferService(store, {
      payloadCipher: new RedactedPayloadCipher(),
      circuitId: manifest.circuitId,
      circuitVersion: manifest.circuitVersion,
      tenantId,
    });
    const preparedId = `zk-tx-prepared-${suffix}`;
    const preparedExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const prepared = await preparation.prepare({
      transactionId: preparedId,
      idempotencyKey: `prepared-${suffix}`,
      productId,
      fee: expectedPublicInputs.fee,
      recipient: expectedPublicInputs.recipient,
      relayer: expectedPublicInputs.relayer,
      authorizedBy: "integration-broker",
      expiresAt: preparedExpiry,
    });
    assert.equal(prepared.state, "PROOF_PENDING");
    assert.equal(prepared.settlementRail, "CONFIDENTIAL_NOTE");
    assert.equal(prepared.legalRegisterApplied, false);
    const preparedRetry = await preparation.prepare({
      transactionId: preparedId,
      idempotencyKey: `prepared-${suffix}`,
      productId,
      fee: expectedPublicInputs.fee,
      recipient: expectedPublicInputs.recipient,
      relayer: expectedPublicInputs.relayer,
      authorizedBy: "integration-broker",
      expiresAt: preparedExpiry,
    });
    assert.equal(preparedRetry.created, false);
    await assert.rejects(preparation.prepare({
      transactionId: preparedId,
      idempotencyKey: `prepared-${suffix}`,
      productId,
      fee: "999",
      recipient: expectedPublicInputs.recipient,
      relayer: expectedPublicInputs.relayer,
      authorizedBy: "integration-broker",
      expiresAt: preparedExpiry,
    }), { code: "IDEMPOTENCY_CONFLICT" });
    await assert.rejects(
      gate.accept({ transactionId: `zk-tx-1-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "ZK_TRANSACTION_NOT_AUTHORIZED" },
    );
    await assert.rejects(
      gate.authorize({ transactionId: `zk-tx-1-${suffix}`, tenantId,
        proofPublicInputs: { ...expectedPublicInputs, fee: BN254_SCALAR_FIELD.toString() } }),
      { code: "INVALID_ZK_AUTHORIZATION" },
    );
    await assert.rejects(
      gate.authorize({ transactionId: `zk-tx-1-${suffix}`, tenantId,
        proofPublicInputs: { ...expectedPublicInputs, recipient: "999" } }),
      { code: "ZK_BUSINESS_CONTEXT_MISMATCH" },
    );
    await assert.rejects(
      gate.authorize({ transactionId: `zk-tx-bad-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs }),
      { code: "INVALID_ZK_EXECUTION_INSTRUCTION" },
    );
    await gate.authorize({ transactionId: `zk-tx-1-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs });
    await gate.authorize({ transactionId: `zk-tx-2-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs });
    await store.pool.query("UPDATE rwa.products SET status='PAUSED' WHERE id=$1", [productId]);
    await assert.rejects(
      gate.accept({ transactionId: `zk-tx-1-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "PRODUCT_NOT_ACTIVE" },
    );
    await store.pool.query("UPDATE rwa.products SET status='ACTIVE' WHERE id=$1", [productId]);
    await assert.rejects(
      store.pool.query("UPDATE rwa.zk_execution_instructions SET recipient=999 WHERE transaction_id=$1", [`zk-tx-1-${suffix}`]),
      { code: "55000" },
    );
    await assert.rejects(
      store.pool.query("UPDATE rwa.zk_product_contexts SET asset_type=999 WHERE product_id=$1", [productId]),
      { code: "55000" },
    );
    await assert.rejects(
      store.pool.query("UPDATE rwa.zk_transaction_authorizations SET recipient=999 WHERE transaction_id=$1", [`zk-tx-1-${suffix}`]),
      { code: "55000" },
    );
    const tamperedSignals = [...publicSignals];
    tamperedSignals[JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.indexOf("recipient")] = "999";
    await assert.rejects(
      gate.accept({ transactionId: `zk-tx-1-${suffix}`, tenantId, proof: { test: true }, publicSignals: tamperedSignals }),
      { code: "PROOF_CONTEXT_MISMATCH" },
    );
    const first = await gate.accept({ transactionId: `zk-tx-1-${suffix}`, tenantId, proof: { test: true }, publicSignals });
    assert.equal(first.verified, true);
    assert.equal(first.proofAccepted, true);
    assert.equal(first.settlementApplied, false);
    assert.equal(first.transactionState, "ROOT_PENDING");
    assert.equal(first.finalityDomain, "CONFIDENTIAL_PROOF_REGISTRY");
    assert.equal(first.legalRegisterApplied, false);
    await gate.proposeFinalization({
      transactionId: `zk-tx-1-${suffix}`, tenantId,
      outputMerkleRoot: (runDomain + 100n).toString(), outputTreeSize: 4,
      rootSourceReference: `root-publication:${suffix}`,
      executionReference: `execution:${suffix}`, proposedBy: "integration-operations-maker",
    });
    await assert.rejects(gate.finalize({
      transactionId: `zk-tx-1-${suffix}`, tenantId, finalizedBy: "integration-operations-maker",
    }), { code: "MAKER_CHECKER_SEPARATION_REQUIRED" });
    const final = await gate.finalize({
      transactionId: `zk-tx-1-${suffix}`, tenantId, finalizedBy: "integration-operations-checker",
    });
    assert.equal(final.settlementApplied, true);
    assert.equal(final.rootPublicationAttested, true);
    assert.equal(final.externalExecutionAttested, true);
    assert.equal(final.state, "SETTLED");
    assert.equal(final.finalityDomain, "CONFIDENTIAL_NOTE_LEDGER");
    await assert.rejects(gate.finalize({
      transactionId: `zk-tx-1-${suffix}`, tenantId, finalizedBy: "a-third-checker",
    }), { code: "UNKNOWN_ZK_TRANSACTION" });
    await assert.rejects(
      store.pool.query("DELETE FROM rwa.zk_merkle_roots WHERE context_id=$1::numeric", [expectedPublicInputs.contextId]),
      { code: "55000" },
    );
    await assert.rejects(gate.accept({ transactionId: `zk-tx-2-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "NULLIFIER_ALREADY_SPENT" });
    await store.pool.query(
      "UPDATE rwa.zk_product_contexts SET retired_at=clock_timestamp() WHERE product_id=$1",
      [productId],
    );
    await assert.rejects(
      gate.accept({ transactionId: `zk-tx-2-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "ZK_BUSINESS_CONTEXT_RETIRED" },
    );
    await assert.rejects(
      gate.accept({ transactionId: `zk-tx-1-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "ZK_TRANSACTION_NOT_AUTHORIZED" },
    );
    const state = await store.pool.query(`SELECT
      (SELECT count(*)::int FROM rwa.zk_proof_receipts WHERE tenant_id=$1) receipts,
      (SELECT count(*)::int FROM rwa.zk_spent_nullifiers n JOIN rwa.zk_proof_receipts r ON r.id=n.proof_receipt_id WHERE r.tenant_id=$1) nullifiers,
      (SELECT count(*)::int FROM rwa.zk_output_commitments o JOIN rwa.zk_proof_receipts r ON r.id=o.proof_receipt_id WHERE r.tenant_id=$1) outputs,
      (SELECT count(*)::int FROM rwa.zk_transaction_authorizations WHERE tenant_id=$1 AND status='VERIFIED') verified_authorizations,
      (SELECT count(*)::int FROM rwa.zk_transaction_authorizations WHERE tenant_id=$1 AND status='PENDING') pending_authorizations,
      (SELECT count(*)::int FROM rwa.zk_settlements WHERE tenant_id=$1) settlements,
      (SELECT count(*)::int FROM rwa.zk_finalization_proposals WHERE tenant_id=$1 AND status='APPROVED') approved_proposals,
      (SELECT count(*)::int FROM rwa.zk_root_publication_attestations WHERE tenant_id=$1) root_attestations,
      (SELECT current_state FROM rwa.transaction_intents WHERE id=$2) first_state,
      (SELECT current_state FROM rwa.transaction_intents WHERE id=$3) second_state`,
    [tenantId, `zk-tx-1-${suffix}`, `zk-tx-2-${suffix}`]);
    assert.deepEqual(state.rows[0], {
      receipts: 1, nullifiers: 2, outputs: 2, verified_authorizations: 1, pending_authorizations: 1,
      settlements: 1, approved_proposals: 1, root_attestations: 1,
      first_state: "SETTLED", second_state: "PROOF_PENDING",
    });
  } finally { await store.close(); }
});
