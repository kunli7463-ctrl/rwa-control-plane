import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { ELIGIBLE_RULES_JSON, insertInstruction, preparedParties, seedConfidentialParties } from "../helpers/confidential-parties.js";
import { fileURLToPath } from "node:url";
import { BN254_SCALAR_FIELD, Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER, verificationKeyHash } from "../../src/security/proof-adapter.js";
import { RedactedPayloadCipher } from "../../src/security/envelope-crypto.js";
import { ConfidentialTransferService } from "../../src/storage/confidential-transfer-service.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ZkSettlementGate } from "../../src/storage/zk-settlement-gate.js";
import { appendMerkleLeaves, emptyMerkleTreeState, merkleLeaf } from "../../src/security/poseidon-merkle.js";

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
  const thirdPublicInputs = {
    ...expectedPublicInputs,
    transactionHash: (runDomain + 20n).toString(),
    inputNullifier0: (runDomain + 21n).toString(),
    inputNullifier1: (runDomain + 22n).toString(),
    outputCommitmentX0: (runDomain + 23n).toString(),
    outputCommitmentX1: (runDomain + 24n).toString(),
    outputCommitmentY0: (runDomain + 25n).toString(),
    outputCommitmentY1: (runDomain + 26n).toString(),
  };
  const thirdPublicSignals = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => thirdPublicInputs[name]);
  const outputLeaves = (inputs) => [
    merkleLeaf(inputs.outputCommitmentX0, inputs.outputCommitmentY0).toString(),
    merkleLeaf(inputs.outputCommitmentX1, inputs.outputCommitmentY1).toString(),
  ];
  try {
    await store.pool.query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'ZK','HK','ACTIVE','test')", [issuerId]);
    await store.pool.query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'ZK','HK',$2,'HKD','ACTIVE',1,$3::jsonb)", [productId, issuerId, ELIGIBLE_RULES_JSON]);
    const parties = await seedConfidentialParties((sql, values) => store.pool.query(sql, values), {
      productId, issuerId, recipientKey: expectedPublicInputs.recipient, suffix,
    });
    await store.pool.query(`INSERT INTO rwa.ledger_accounts
      (id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ($1,$2,$3,'zk-owner',$4,'INVESTOR')`,
    [`ledger:${productId}:tenant-boundary`, tenantId, productId, `UNIT:${productId}`]);
    for (const transactionId of [`zk-tx-1-${suffix}`, `zk-tx-2-${suffix}`, `zk-tx-3-${suffix}`, `zk-tx-bad-${suffix}`]) {
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
    const query = (sql, values) => store.pool.query(sql, values);
    await assert.rejects(query(`INSERT INTO rwa.zk_execution_instructions
      (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by)
      VALUES ($1,$2,$3,0,1,0,'party-less')`, [`zk-tx-1-${suffix}`, tenantId, "a".repeat(64)]), { code: "23514" });
    for (const transactionId of [`zk-tx-1-${suffix}`, `zk-tx-2-${suffix}`, `zk-tx-3-${suffix}`]) {
      await insertInstruction(query, { transactionId, tenantId, requestHash: "a".repeat(64),
        fee: expectedPublicInputs.fee, recipient: expectedPublicInputs.recipient, relayer: expectedPublicInputs.relayer,
        parties, authorizedBy: "integration-authorizer" });
    }
    await insertInstruction(query, { transactionId: `zk-tx-bad-${suffix}`, tenantId, requestHash: "c".repeat(64),
      fee: expectedPublicInputs.fee, recipient: expectedPublicInputs.recipient, relayer: expectedPublicInputs.relayer,
      parties, authorizedBy: "integration-authorizer" });
    await assert.rejects(
      store.pool.query(`INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,status,observed_at,source_reference)
        VALUES ($1::numeric,$2::numeric,2,'CURRENT',clock_timestamp(),'frontier-less')`,
      [expectedPublicInputs.contextId, expectedPublicInputs.merkleRoot]),
      { code: "23514" },
    );
    // The proofs in this test are against an externally observed historical
    // root; the extendable CURRENT tree starts empty and carries its frontier.
    await store.pool.query(`INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,status,observed_at,expires_at,source_reference)
      VALUES ($1::numeric,$2::numeric,2,'HISTORICAL',clock_timestamp(),clock_timestamp()+interval '1 day','integration-test')`,
    [expectedPublicInputs.contextId, expectedPublicInputs.merkleRoot]);
    const genesis = emptyMerkleTreeState();
    await store.pool.query(`INSERT INTO rwa.zk_merkle_roots(context_id,merkle_root,tree_size,frontier,status,observed_at,source_reference)
      VALUES ($1::numeric,$2::numeric,0,$3::jsonb,'CURRENT',clock_timestamp(),'integration-genesis')`,
    [expectedPublicInputs.contextId, genesis.root, JSON.stringify(genesis.frontier)]);
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
      originatingInstitutionId: issuerId,
      ...preparedParties(parties),
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
      originatingInstitutionId: issuerId,
      ...preparedParties(parties),
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
      originatingInstitutionId: issuerId,
      ...preparedParties(parties),
    }), { code: "IDEMPOTENCY_CONFLICT" });
    const preparedBase = {
      productId, fee: expectedPublicInputs.fee, recipient: expectedPublicInputs.recipient,
      relayer: expectedPublicInputs.relayer, authorizedBy: "integration-broker", expiresAt: preparedExpiry,
      originatingInstitutionId: issuerId,
    };
    await assert.rejects(preparation.prepare({ ...preparedBase, originatingInstitutionId: undefined,
      idempotencyKey: `no-institution-${suffix}`, ...preparedParties(parties) }), { code: "AUTHORIZATION_DENIED" });
    await assert.rejects(preparation.prepare({ ...preparedBase, idempotencyKey: `no-parties-${suffix}` }),
      { code: "INVALID_CONFIDENTIAL_INSTRUCTION" });
    await assert.rejects(preparation.prepare({ ...preparedBase, idempotencyKey: `unregistered-${suffix}`,
      ...preparedParties(parties), recipient: "424242" }), { code: "RECIPIENT_KEY_NOT_REGISTERED" });
    await assert.rejects(preparation.prepare({ ...preparedBase, idempotencyKey: `wrong-owner-${suffix}`,
      ...preparedParties({ sender: parties.recipient, recipient: parties.sender }) }), { code: "RECIPIENT_KEY_NOT_REGISTERED" });
    await query("UPDATE rwa.credentials SET status='RESTRICTED_EXIT',restriction_reason='test' WHERE id=$1", [parties.sender.credentialId]);
    const restricted = await preparation.prepare({ ...preparedBase, idempotencyKey: `restricted-${suffix}`,
      ...preparedParties(parties) }).catch((error) => error);
    assert.equal(restricted.code, "CONFIDENTIAL_PARTY_INELIGIBLE");
    assert.deepEqual(restricted.details, { party: "sender", reason: "CREDENTIAL_RESTRICTED" });
    await assert.rejects(gate.authorize({ transactionId: `zk-tx-1-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs }),
      { code: "CONFIDENTIAL_PARTY_INELIGIBLE" });
    await query("UPDATE rwa.credentials SET status='ACTIVE',restriction_reason=NULL WHERE id=$1", [parties.sender.credentialId]);
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
    await assert.rejects(gate.authorize({ transactionId: preparedId, tenantId, proofPublicInputs: expectedPublicInputs,
      actorInstitutionId: "another-institution" }), { code: "UNKNOWN_ZK_TRANSACTION" });
    await assert.rejects(gate.authorize({ transactionId: preparedId, tenantId, proofPublicInputs: expectedPublicInputs,
      actorInstitutionId: "" }), { code: "UNKNOWN_ZK_TRANSACTION" });
    await gate.authorize({ transactionId: `zk-tx-1-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs });
    await gate.authorize({ transactionId: `zk-tx-2-${suffix}`, tenantId, proofPublicInputs: expectedPublicInputs });
    await gate.authorize({ transactionId: `zk-tx-3-${suffix}`, tenantId, proofPublicInputs: thirdPublicInputs });
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
    await assert.rejects(
      store.pool.query("UPDATE rwa.transaction_intents SET current_state='REJECTED' WHERE id=$1", [`zk-tx-1-${suffix}`]),
      { code: "23514" },
    );
    await assert.rejects(
      store.pool.query("UPDATE rwa.transaction_intents SET current_state='REQUIRES_REVIEW' WHERE id=$1", [`zk-tx-1-${suffix}`]),
      { code: "23514" },
    );
    const third = await gate.accept({ transactionId: `zk-tx-3-${suffix}`, tenantId, proof: { test: true }, publicSignals: thirdPublicSignals });
    assert.equal(third.transactionState, "ROOT_PENDING");
    const proposal = (transactionId, outputMerkleRoot, outputTreeSize) => gate.proposeFinalization({
      transactionId, tenantId, outputMerkleRoot, outputTreeSize,
      rootSourceReference: `root-publication:${suffix}`,
      executionReference: `execution:${suffix}`, proposedBy: "integration-operations-maker",
    });
    // An attested but unverifiable root is refused, with the expected value returned.
    const firstExtension = appendMerkleLeaves(genesis, outputLeaves(expectedPublicInputs));
    const forged = await proposal(`zk-tx-1-${suffix}`, (runDomain + 100n).toString(), 2).catch((error) => error);
    assert.equal(forged.code, "ROOT_PUBLICATION_MISMATCH");
    assert.equal(forged.details.expectedMerkleRoot, firstExtension.root);
    assert.equal(forged.details.expectedTreeSize, 2);
    await assert.rejects(proposal(`zk-tx-1-${suffix}`, firstExtension.root, 4), { code: "ROOT_PUBLICATION_MISMATCH" });
    // Both root-pending transactions propose against the same base tree.
    await proposal(`zk-tx-1-${suffix}`, firstExtension.root, 2);
    await assert.rejects(proposal(`zk-tx-1-${suffix}`, firstExtension.root, 2), { code: "ROOT_FINALIZATION_ALREADY_PROPOSED" });
    const thirdOnGenesis = appendMerkleLeaves(genesis, outputLeaves(thirdPublicInputs));
    await proposal(`zk-tx-3-${suffix}`, thirdOnGenesis.root, 2);
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
    // The third proposal was built on the genesis root. Approving it would
    // silently drop the first transaction's outputs, so it is cancelled.
    const stale = await gate.finalize({
      transactionId: `zk-tx-3-${suffix}`, tenantId, finalizedBy: "integration-operations-checker",
    }).catch((error) => error);
    assert.equal(stale.code, "STALE_ROOT_PUBLICATION");
    const thirdExtension = appendMerkleLeaves({ ...firstExtension, expectedRoot: firstExtension.root }, outputLeaves(thirdPublicInputs));
    assert.equal(stale.details.expectedMerkleRoot, thirdExtension.root);
    assert.equal(stale.details.currentMerkleRoot, firstExtension.root);
    await assert.rejects(gate.cancelFinalization({
      transactionId: `zk-tx-3-${suffix}`, tenantId, cancelledBy: "integration-operations-maker", reason: "already cancelled",
    }), { code: "ROOT_FINALIZATION_NOT_PENDING" });
    await proposal(`zk-tx-3-${suffix}`, thirdExtension.root, 4);
    await gate.cancelFinalization({
      transactionId: `zk-tx-3-${suffix}`, tenantId, cancelledBy: "integration-operations-checker",
      reason: "external publication batch was withdrawn",
    });
    await proposal(`zk-tx-3-${suffix}`, thirdExtension.root, 4);
    const thirdFinal = await gate.finalize({
      transactionId: `zk-tx-3-${suffix}`, tenantId, finalizedBy: "integration-operations-checker",
    });
    assert.equal(thirdFinal.outputMerkleRoot, thirdExtension.root);
    assert.equal(thirdFinal.baseMerkleRoot, firstExtension.root);
    assert.equal(thirdFinal.rootVerification, "SERVER_RECOMPUTED");
    const roots = await store.pool.query(
      `SELECT merkle_root::text,tree_size,status FROM rwa.zk_merkle_roots
       WHERE context_id=$1::numeric AND frontier IS NOT NULL ORDER BY tree_size`,
      [expectedPublicInputs.contextId],
    );
    assert.deepEqual(roots.rows.map((root) => [root.merkle_root, Number(root.tree_size), root.status]), [
      [genesis.root, 0, "HISTORICAL"], [firstExtension.root, 2, "HISTORICAL"], [thirdExtension.root, 4, "CURRENT"],
    ]);
    await assert.rejects(
      store.pool.query("UPDATE rwa.zk_merkle_roots SET frontier='[]'::jsonb WHERE context_id=$1::numeric AND status='CURRENT'", [expectedPublicInputs.contextId]),
      { code: "55000" },
    );
    await assert.rejects(
      store.pool.query("DELETE FROM rwa.zk_merkle_roots WHERE context_id=$1::numeric", [expectedPublicInputs.contextId]),
      { code: "55000" },
    );
    await assert.rejects(gate.accept({ transactionId: `zk-tx-2-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "NULLIFIER_ALREADY_SPENT" });
    // Revoking the recipient's note owner key after authorization blocks acceptance.
    await query(`UPDATE rwa.confidential_note_owner_keys SET status='REVOKED',revoked_by='test',revoked_at=clock_timestamp(),revoke_reason='compromised'
      WHERE product_id=$1`, [productId]);
    await assert.rejects(gate.accept({ transactionId: `zk-tx-2-${suffix}`, tenantId, proof: { test: true }, publicSignals }),
      { code: "RECIPIENT_KEY_NOT_REGISTERED" });
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
      receipts: 2, nullifiers: 4, outputs: 4, verified_authorizations: 2, pending_authorizations: 1,
      settlements: 2, approved_proposals: 2, root_attestations: 2,
      first_state: "SETTLED", second_state: "PROOF_PENDING",
    });
  } finally { await store.close(); }
});
