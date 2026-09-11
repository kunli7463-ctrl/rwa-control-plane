import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ControlPlane, createSandboxInstitution } from "../../src/control-plane.js";
import { DurableWorkflowService } from "../../src/storage/durable-workflow-service.js";
import { AesGcmEnvelopeCipher, LocalKeyring } from "../../src/security/envelope-crypto.js";
import { deriveEconomicCommitmentKey, EconomicCommitter } from "../../src/security/economic-commitment.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { PostgresReadModel } from "../../src/storage/postgres-read-model.js";

const enabled = Boolean(process.env.DATABASE_URL);
const NOW = new Date("2026-08-23T12:00:00Z");

function scenario(suffix) {
  const plane = new ControlPlane({ now: () => new Date(NOW) });
  const productId = `durable-product-${suffix}`;
  const specs = {
    issuer: ["issuer"], broker: ["distributor"], kyc: ["credential_issuer"],
    admin: ["fund_administrator"], custodian: ["custodian"],
    registrar: ["transfer_agent"], bank: ["cash_provider"],
  };
  const institutions = Object.fromEntries(Object.entries(specs).map(([name, roles]) => {
    const id = `durable-${name}-${suffix}`;
    return [name, createSandboxInstitution({ id, roles })];
  }));
  for (const item of Object.values(institutions)) plane.registerInstitution(item.institution);
  plane.createProduct({
    id: productId,
    name: "Durable Workflow Test Fund",
    jurisdiction: "HK",
    issuerId: institutions.issuer.institution.id,
    roleAssignments: Object.fromEntries(Object.entries(institutions).map(([role, value]) => [
      ({ broker: "distributor", kyc: "credential_issuer", admin: "fund_administrator", registrar: "transfer_agent", bank: "cash_provider" })[role] ?? role,
      value.institution.id,
    ])),
    rules: {
      currency: "HKD",
      allowedInvestorClasses: ["professional"],
      allowedJurisdictions: ["HK"],
      maxPriceDeviationBps: 100,
    },
  });
  plane.activateProduct(productId);
  plane.submitEvidence(institutions.admin.signStatement({
    id: `durable-nav-${suffix}`,
    productId,
    dataType: "nav",
    sourceInstitutionId: institutions.admin.institution.id,
    trustTier: "A",
    effectiveAt: "2026-08-23T00:00:00Z",
    expiresAt: "2026-08-24T00:00:00Z",
    schemaVersion: "1.0.0",
    payload: { navPerUnit: "10000", currency: "HKD" },
  }));
  for (const subjectId of [`durable-alice-${suffix}`, `durable-bob-${suffix}`]) {
    plane.registerCredential(institutions.kyc.signStatement({
      id: `credential-${subjectId}`,
      issuerId: institutions.kyc.institution.id,
      subjectId,
      productId,
      investorClass: "professional",
      jurisdiction: "HK",
      maxUnits: "1000",
      validFrom: "2026-08-01T00:00:00Z",
      validUntil: "2027-08-01T00:00:00Z",
      revocationHandle: `revoke-${subjectId}`,
    }));
    plane.creditSandboxCash(subjectId, "HKD", "2000000");
  }
  return { plane, productId, alice: `durable-alice-${suffix}`, bob: `durable-bob-${suffix}` };
}

test("durable subscribe, transfer and redeem commit ledgers, register, audit and outbox atomically", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const masterKey = randomBytes(32);
  const payloadCipher = new AesGcmEnvelopeCipher(new LocalKeyring({
    activeKeyId: "integration-k1",
    keys: { "integration-k1": masterKey },
  }));
  const economicCommitter = new EconomicCommitter({ key: deriveEconomicCommitmentKey(masterKey), keyId: "integration-economic-k1" });
  const service = new DurableWorkflowService(store, {
    now: () => new Date(NOW), tenantId: "integration", payloadCipher, economicCommitter,
  });
  const readModel = new PostgresReadModel(store, { payloadCipher, tenantId: "integration" });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const data = scenario(suffix);
  await service.bootstrapFromControlPlane(data.plane);

  const subscriptionRequest = {
    id: `durable-sub-${suffix}`,
    idempotencyKey: `idem-sub-${suffix}`,
    productId: data.productId,
    investorId: data.alice,
    credentialId: `credential-${data.alice}`,
    units: "100",
    cashAmount: "1000000",
  };
  const subscription = await service.subscribe(subscriptionRequest);
  const duplicate = await service.subscribe(subscriptionRequest);
  assert.deepEqual(duplicate, subscription);

  await service.transfer({
    id: `durable-transfer-${suffix}`,
    idempotencyKey: `idem-transfer-${suffix}`,
    productId: data.productId,
    sellerId: data.alice,
    sellerCredentialId: `credential-${data.alice}`,
    buyerId: data.bob,
    buyerCredentialId: `credential-${data.bob}`,
    units: "20",
    pricePerUnit: "10000",
    fee: "100",
    expiresAt: "2026-08-23T12:05:00Z",
  });
  const redemption = await service.redeem({
    id: `durable-redeem-${suffix}`,
    idempotencyKey: `idem-redeem-${suffix}`,
    productId: data.productId,
    investorId: data.bob,
    credentialId: `credential-${data.bob}`,
    units: "5",
  });

  assert.equal(subscription.state, "SETTLED");
  assert.equal(redemption.state, "SETTLED");
  for (const forbidden of ["investorId", "sellerId", "buyerId", "units", "cashAmount", "pricePerUnit"]) {
    assert.equal(forbidden in subscription, false);
  }
  const brokerDisclosure = await readModel.transactionForRole({
    transactionId: subscriptionRequest.id, role: "broker", actorRef: "authorized-broker",
  });
  assert.equal(brokerDisclosure.privatePayload.cashAmount, "1000000");
  assert.equal(brokerDisclosure.disclosure, "AUTHORIZED_BROKER_FULL");
  const partyDisclosure = await readModel.transactionForRole({
    transactionId: subscriptionRequest.id, role: "investor", actorRef: data.alice,
  });
  assert.equal(partyDisclosure.privatePayload.units, "100");
  await assert.rejects(
    readModel.transactionForRole({ transactionId: subscriptionRequest.id, role: "investor", actorRef: data.bob }),
    { code: "DISCLOSURE_DENIED" },
  );
  const supervisorDisclosure = await readModel.transactionForRole({
    transactionId: subscriptionRequest.id, role: "supervisor", actorRef: "supervisor-1",
  });
  assert.equal("privatePayload" in supervisorDisclosure, false);
  assert.equal(supervisorDisclosure.disclosure, "METADATA_ONLY");

  const issuerView = await readModel.viewForRole({ productId: data.productId, role: "issuer" });
  assert.equal(issuerView.storageMode, "POSTGRESQL");
  assert.equal(issuerView.reconciliation.confidentialAssetUnits, "95");
  assert.equal(issuerView.reconciliation.legalRegisterUnits, "95");
  assert.equal(issuerView.reconciliation.assetRegisterMatched, true);
  assert.equal(issuerView.reconciliation.cashConfirmedCount, 3);
  assert.equal(issuerView.transactionSummary.length, 3);

  const investorView = await readModel.viewForRole({
    productId: data.productId, role: "investor", actorRef: data.alice,
  });
  assert.equal(investorView.positionUnits, "80");
  assert.equal(investorView.ownTransactions.length, 2);
  assert.ok(investorView.ownTransactions.every((item) => !item.id.includes("redeem")));

  const brokerView = await readModel.viewForRole({ productId: data.productId, role: "broker" });
  assert.equal(brokerView.transactions.length, 3);
  assert.equal(brokerView.transactions.find((item) => item.type === "TRANSFER").sellerId, data.alice);

  const distributorView = await readModel.viewForRole({ productId: data.productId, role: "distributor" });
  assert.equal(distributorView.credentials.length, 2);
  assert.ok(distributorView.credentials.every((item) => item.status === "ACTIVE"));

  const operationsView = await readModel.viewForRole({ productId: data.productId, role: "operations" });
  assert.equal(operationsView.exceptions.length, 0);
  assert.equal(operationsView.transactionSummary.length, 3);

  const supervisorView = await readModel.viewForRole({ productId: data.productId, role: "supervisor" });
  assert.equal(supervisorView.disclosureMode, "POSTGRESQL_METADATA_ONLY");
  assert.equal(supervisorView.auditEvents.length, 3);
  assert.ok(supervisorView.auditEvents.every((item) => !("privatePayload" in item)));

  const evidencePackage = await readModel.transactionEvidencePackage({ transactionId: subscriptionRequest.id, role: "supervisor" });
  const repeatedEvidencePackage = await readModel.transactionEvidencePackage({ transactionId: subscriptionRequest.id, role: "supervisor" });
  assert.equal(evidencePackage.packageHash, repeatedEvidencePackage.packageHash);
  assert.ok(evidencePackage.stateHistory.every((item) => item.actorRef === "[REDACTED]"));
  assert.equal(evidencePackage.transaction.state, "SETTLED");
  assert.equal(evidencePackage.disclosure, "NO_PRIVATE_ECONOMICS_IDENTIFIERS_REDACTED");
  assert.equal("privatePayload" in evidencePackage, false);

  const otherTenantReadModel = new PostgresReadModel(store, {
    payloadCipher, tenantId: `other-${suffix}`, now: () => new Date(NOW),
  });
  await assert.rejects(
    otherTenantReadModel.viewForRole({ productId: data.productId, role: "issuer" }),
    { code: "UNKNOWN_PRODUCT" },
  );

  const client = await store.pool.connect();
  try {
    const state = await client.query(
      "SELECT current_state,count(*) OVER ()::int AS total FROM rwa.transaction_intents WHERE product_id=$1 ORDER BY id",
      [data.productId],
    );
    assert.equal(state.rowCount, 3);
    assert.ok(state.rows.every((row) => row.current_state === "SETTLED"));

    const unitAsset = `UNIT:${data.productId}`;
    const reconciliation = await client.query(
      `WITH asset AS (
         SELECT a.owner_ref,sum(e.signed_delta)::text AS balance
         FROM rwa.ledger_entries e JOIN rwa.ledger_accounts a ON a.id=e.account_id
         WHERE a.product_id=$1 AND e.asset_code=$2 GROUP BY a.owner_ref
       ), register AS (
         SELECT a.owner_ref,sum(e.signed_delta)::text AS balance
         FROM rwa.register_entries e JOIN rwa.register_accounts a ON a.id=e.account_id
         WHERE a.product_id=$1 AND e.asset_code=$2 GROUP BY a.owner_ref
       )
       SELECT COALESCE(asset.owner_ref,register.owner_ref) AS owner_ref,asset.balance AS asset_balance,register.balance AS register_balance
       FROM asset FULL JOIN register USING (owner_ref)
       WHERE asset.balance IS DISTINCT FROM register.balance`,
      [data.productId, unitAsset],
    );
    assert.equal(reconciliation.rowCount, 0);

    const controls = await client.query(
      `SELECT
         (SELECT count(*)::int FROM rwa.outbox_events WHERE aggregate_id LIKE $1) AS outbox_count,
         (SELECT count(*)::int FROM rwa.audit_events WHERE aggregate_id LIKE $1) AS audit_count,
         (SELECT count(*)::int FROM rwa.transaction_receipts r JOIN rwa.transaction_intents t ON t.id=r.transaction_id WHERE t.product_id=$2) AS receipt_count`,
      [`durable-%-${suffix}`, data.productId],
    );
    assert.deepEqual(controls.rows[0], { outbox_count: 3, audit_count: 3, receipt_count: 3 });

    const brokenId = `durable-broken-${suffix}`;
    await assert.rejects(
      store.withSerializableTransaction(async (transactionClient) => {
        await store.createTransactionIntent(transactionClient, {
          id: brokenId,
          tenantId: "integration",
          productId: data.productId,
          idempotencyKey: `idem-${brokenId}`,
          request: { id: brokenId, purpose: "atomicity-fault-injection" },
          transactionType: "TRANSFER",
          ruleVersion: 1,
          navEvidenceId: `durable-nav-${suffix}`,
          policySnapshotHash: "c".repeat(64),
          privatePayloadCiphertext: Buffer.from("SANDBOX_REDACTED"),
          actorRef: "integration-test",
        });
        for (const toState of ["POLICY_CHECKED", "CASH_RESERVED", "REGISTER_PENDING"]) {
          await store.transitionTransaction(transactionClient, { transactionId: brokenId, toState, actorRef: "integration-test" });
        }
        await store.appendLedgerBatch(transactionClient, {
          batchId: `ledger:${brokenId}`,
          transactionId: brokenId,
          entries: [
            { accountId: `ledger:${data.productId}:${data.alice}:${unitAsset}:INVESTOR`, assetCode: unitAsset, signedDelta: "-10" },
            { accountId: `ledger:${data.productId}:${data.bob}:${unitAsset}:INVESTOR`, assetCode: unitAsset, signedDelta: "10" },
          ],
        });
        await store.appendRegisterBatch(transactionClient, {
          batchId: `register:${brokenId}`,
          transactionId: brokenId,
          assetCode: unitAsset,
          entries: [
            { accountId: `register:${data.productId}:${data.alice}:${unitAsset}:INVESTOR`, assetCode: unitAsset, signedDelta: "-9" },
            { accountId: `register:${data.productId}:${data.bob}:${unitAsset}:INVESTOR`, assetCode: unitAsset, signedDelta: "9" },
          ],
        });
      }),
      /does not mirror the asset ledger/,
    );
    const rolledBack = await client.query(
      `SELECT
         (SELECT count(*)::int FROM rwa.transaction_intents WHERE id=$1) AS transaction_count,
         (SELECT count(*)::int FROM rwa.ledger_batches WHERE id=$2) AS ledger_count,
         (SELECT count(*)::int FROM rwa.register_batches WHERE id=$3) AS register_count`,
      [brokenId, `ledger:${brokenId}`, `register:${brokenId}`],
    );
    assert.deepEqual(rolledBack.rows[0], { transaction_count: 0, ledger_count: 0, register_count: 0 });
  } finally {
    client.release();
    await service.close();
  }
});

test("PostgreSQL control, restriction and multi-round exception workflows remain atomic", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const masterKey = randomBytes(32);
  const payloadCipher = new AesGcmEnvelopeCipher(new LocalKeyring({
    activeKeyId: "control-k1",
    keys: { "control-k1": masterKey },
  }));
  const economicCommitter = new EconomicCommitter({ key: deriveEconomicCommitmentKey(masterKey), keyId: "control-economic-k1" });
  const service = new DurableWorkflowService(store, {
    now: () => new Date(NOW), tenantId: "control-integration", payloadCipher, economicCommitter,
  });
  const readModel = new PostgresReadModel(store, {
    payloadCipher, tenantId: "control-integration", now: () => new Date(NOW),
  });
  const suffix = `control-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const data = scenario(suffix);
  await service.bootstrapFromControlPlane(data.plane);

  try {
    await service.subscribe({
      id: `control-sub-${suffix}`,
      idempotencyKey: `control-sub-${suffix}`,
      productId: data.productId,
      investorId: data.alice,
      credentialId: `credential-${data.alice}`,
      units: "100",
      cashAmount: "1000000",
    });

    await service.setProductStatus({
      productId: data.productId, status: "PAUSED", actorRef: "issuer-maker", reason: "control test",
    });
    await assert.rejects(service.subscribe({
      id: `paused-sub-${suffix}`,
      idempotencyKey: `paused-sub-${suffix}`,
      productId: data.productId,
      investorId: data.alice,
      credentialId: `credential-${data.alice}`,
      units: "1",
      cashAmount: "10000",
    }), { code: "PRODUCT_NOT_ACTIVE" });
    await service.setProductStatus({
      productId: data.productId, status: "ACTIVE", actorRef: "issuer-checker", reason: "control test complete",
    });

    const before = await readModel.viewForRole({ productId: data.productId, role: "issuer" });
    const failureRequests = [1, 2].map((index) => ({
      id: `control-failure-${index}-${suffix}`,
      idempotencyKey: `control-failure-${index}-${suffix}`,
      productId: data.productId,
      sellerId: data.alice,
      sellerCredentialId: `credential-${data.alice}`,
      buyerId: data.bob,
      buyerCredentialId: `credential-${data.bob}`,
      units: "10",
      pricePerUnit: "10000",
      fee: "100",
      expiresAt: "2026-08-23T12:05:00Z",
    }));
    const firstFailure = await service.simulateRegisterFailure(failureRequests[0]);
    const secondFailure = await service.simulateRegisterFailure(failureRequests[1]);
    assert.equal(firstFailure.state, "REQUIRES_REVIEW");
    assert.equal(secondFailure.reasonCode, "REGISTER_TIMEOUT");
    const afterFailures = await readModel.viewForRole({ productId: data.productId, role: "issuer" });
    assert.equal(afterFailures.reconciliation.confidentialAssetUnits, before.reconciliation.confidentialAssetUnits);
    assert.equal(afterFailures.reconciliation.legalRegisterUnits, before.reconciliation.legalRegisterUnits);

    const replacementId = `control-replacement-${suffix}`;
    await service.proposeExceptionResolution({
      caseId: firstFailure.exceptionCaseId,
      makerId: "operations-maker",
      decision: "RETRY",
      replacementTransactionId: replacementId,
    });
    await assert.rejects(service.approveExceptionResolution({
      caseId: firstFailure.exceptionCaseId,
      checkerId: "operations-maker",
    }), { code: "MAKER_CHECKER_CONFLICT" });
    const retried = await service.approveExceptionResolution({
      caseId: firstFailure.exceptionCaseId,
      checkerId: "operations-checker",
    });
    assert.equal(retried.state, "RESOLVED_RETRIED");
    assert.equal(retried.replacement.transactionId, replacementId);

    await service.proposeExceptionResolution({
      caseId: secondFailure.exceptionCaseId,
      makerId: "operations-maker",
      decision: "RETRY",
      replacementTransactionId: `blocked-replacement-${suffix}`,
    });
    await service.restrictCredential({
      credentialId: `credential-${data.bob}`,
      actorRef: "credential-operator",
      reason: "eligibility changed during review",
    });
    const blocked = await service.approveExceptionResolution({
      caseId: secondFailure.exceptionCaseId,
      checkerId: "operations-checker",
    });
    assert.equal(blocked.state, "OPEN");
    assert.equal(blocked.retryBlocked, true);
    assert.equal(blocked.reasonCode, "CREDENTIAL_REVOKED");

    await service.proposeExceptionResolution({
      caseId: secondFailure.exceptionCaseId,
      makerId: "operations-maker-2",
      decision: "CANCEL",
    });
    const cancelled = await service.approveExceptionResolution({
      caseId: secondFailure.exceptionCaseId,
      checkerId: "operations-checker-2",
    });
    assert.equal(cancelled.state, "RESOLVED_CANCELLED");

    await assert.rejects(service.transfer({
      ...failureRequests[0],
      id: `restricted-transfer-${suffix}`,
      idempotencyKey: `restricted-transfer-${suffix}`,
    }), { code: "CREDENTIAL_REVOKED" });
    const restrictedExit = await service.redeem({
      id: `restricted-redeem-${suffix}`,
      idempotencyKey: `restricted-redeem-${suffix}`,
      productId: data.productId,
      investorId: data.bob,
      credentialId: `credential-${data.bob}`,
      units: "5",
    });
    assert.equal(restrictedExit.settlementMode, "RESTRICTED_EXIT");

    const controls = await store.pool.query(
      `SELECT e.status,e.approval_round,
              (SELECT count(*)::int FROM rwa.approval_records a WHERE a.exception_id=e.id) AS approval_count,
              (SELECT state FROM rwa.cash_confirmations c WHERE c.transaction_id=e.transaction_id) AS cash_state
       FROM rwa.exception_cases e WHERE e.id = ANY($1::text[]) ORDER BY e.id`,
      [[firstFailure.exceptionCaseId, secondFailure.exceptionCaseId]],
    );
    assert.deepEqual(controls.rows.map((row) => row.status).sort(), ["RESOLVED_CANCELLED", "RESOLVED_RETRIED"]);
    const cancelledRow = controls.rows.find((row) => row.status === "RESOLVED_CANCELLED");
    assert.equal(cancelledRow.approval_round, 2);
    assert.equal(cancelledRow.approval_count, 4);
    assert.ok(controls.rows.every((row) => row.cash_state === "RELEASED"));

    const finalView = await readModel.viewForRole({ productId: data.productId, role: "issuer" });
    assert.equal(finalView.reconciliation.confidentialAssetUnits, "95");
    assert.equal(finalView.reconciliation.legalRegisterUnits, "95");
    assert.equal(finalView.reconciliation.assetRegisterMatched, true);
  } finally {
    await service.close();
  }
});
