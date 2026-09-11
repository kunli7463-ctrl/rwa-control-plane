import assert from "node:assert/strict";
import test from "node:test";
import { ControlPlane, createSandboxInstitution } from "../src/control-plane.js";

const NOW = new Date("2026-08-23T12:00:00Z");

function setup({ cashAmount = "10000000" } = {}) {
  const plane = new ControlPlane({ now: () => new Date(NOW) });
  const specs = {
    issuer: ["issuer"],
    broker: ["distributor"],
    kyc: ["credential_issuer"],
    admin: ["fund_administrator"],
    custodian: ["custodian"],
    registrar: ["transfer_agent"],
    bank: ["cash_provider"],
  };
  const institutions = Object.fromEntries(
    Object.entries(specs).map(([id, roles]) => [id, createSandboxInstitution({ id, roles })]),
  );
  for (const value of Object.values(institutions)) plane.registerInstitution(value.institution);

  plane.createProduct({
    id: "fund-hk-001",
    name: "Sandbox HK Liquidity Fund",
    jurisdiction: "HK",
    issuerId: "issuer",
    roleAssignments: {
      issuer: "issuer",
      distributor: "broker",
      credential_issuer: "kyc",
      fund_administrator: "admin",
      custodian: "custodian",
      transfer_agent: "registrar",
      cash_provider: "bank",
    },
    rules: {
      currency: "HKD",
      allowedInvestorClasses: ["professional"],
      allowedJurisdictions: ["HK", "AE"],
      maxPriceDeviationBps: 100,
    },
  });
  plane.activateProduct("fund-hk-001");

  const evidenceBase = {
    productId: "fund-hk-001",
    trustTier: "A",
    effectiveAt: "2026-08-23T00:00:00Z",
    expiresAt: "2026-08-24T00:00:00Z",
    schemaVersion: "1.0.0",
  };
  plane.submitEvidence(
    institutions.admin.signStatement({
      ...evidenceBase,
      id: "nav-001",
      dataType: "nav",
      sourceInstitutionId: "admin",
      payload: { navPerUnit: "10000", currency: "HKD" },
    }),
  );

  for (const subjectId of ["alice", "bob"]) {
    plane.registerCredential(
      institutions.kyc.signStatement({
        id: `cred-${subjectId}`,
        issuerId: "kyc",
        subjectId,
        productId: "fund-hk-001",
        investorClass: "professional",
        jurisdiction: "HK",
        maxUnits: "1000",
        validFrom: "2026-08-01T00:00:00Z",
        validUntil: "2027-08-01T00:00:00Z",
        revocationHandle: `rev-${subjectId}`,
      }),
    );
  }
  plane.creditSandboxCash("alice", "HKD", cashAmount);
  plane.creditSandboxCash("bob", "HKD", cashAmount);
  return { plane, institutions };
}

test("subscription, confidential transfer and redemption keep asset/register ledgers equal", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-1",
    idempotencyKey: "idem-sub-1",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "100",
    cashAmount: "1000000",
  });
  const receipt = plane.transfer({
    id: "tx-transfer-1",
    idempotencyKey: "idem-transfer-1",
    productId: "fund-hk-001",
    sellerId: "alice",
    sellerCredentialId: "cred-alice",
    buyerId: "bob",
    buyerCredentialId: "cred-bob",
    units: "20",
    pricePerUnit: "10000",
    fee: "100",
    expiresAt: "2026-08-23T12:05:00Z",
  });
  plane.redeem({
    id: "tx-redeem-1",
    idempotencyKey: "idem-redeem-1",
    productId: "fund-hk-001",
    investorId: "bob",
    credentialId: "cred-bob",
    units: "5",
  });

  assert.equal(receipt.proofSystem, "SANDBOX_NO_ZK_PROOF");
  assert.equal("buyerId" in receipt, false);
  assert.equal("units" in receipt, false);
  assert.deepEqual(plane.reconcile("fund-hk-001"), {
    productId: "fund-hk-001",
    confidentialAssetUnits: "95",
    legalRegisterUnits: "95",
    assetRegisterMatched: true,
    cashExpectedCount: 3,
    cashConfirmedCount: 3,
    cashControlMode: "SANDBOX_JOURNAL_NOT_BANK_RECEIPT",
    cashConfirmed: true,
    openExceptionCount: 0,
    matched: true,
    overallStatus: "SANDBOX_CONTROLLED",
    checkedAt: NOW.toISOString(),
  });
  assert.deepEqual(receipt.lifecycle, [
    "REQUESTED",
    "POLICY_CHECKED",
    "CASH_RESERVED",
    "REGISTER_PENDING",
    "SETTLED",
  ]);
});

test("revoked buyer credential blocks transfer without changing balances", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-1",
    idempotencyKey: "idem-sub-1",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "100",
    cashAmount: "1000000",
  });
  const before = plane.reconcile("fund-hk-001");
  plane.revokeCredential("cred-bob", "sandbox sanctions update");
  assert.throws(
    () =>
      plane.transfer({
        id: "tx-transfer-revoked",
        idempotencyKey: "idem-transfer-revoked",
        productId: "fund-hk-001",
        sellerId: "alice",
        sellerCredentialId: "cred-alice",
        buyerId: "bob",
        buyerCredentialId: "cred-bob",
        units: "20",
        pricePerUnit: "10000",
        expiresAt: "2026-08-23T12:05:00Z",
      }),
    (error) => error.code === "CREDENTIAL_REVOKED",
  );
  assert.equal(plane.reconcile("fund-hk-001").confidentialAssetUnits, before.confidentialAssetUnits);
  const rejected = plane.eventsForAudit().find(
    (event) => event.type === "transaction.rejected" && event.transactionId === "tx-transfer-revoked",
  );
  assert.equal(rejected.reasonCode, "CREDENTIAL_REVOKED");
  assert.equal("units" in rejected, false);
  assert.equal("cashAmount" in rejected, false);
});

test("restricted credential blocks inbound acquisition but permits controlled redemption exit", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-b",
    idempotencyKey: "idem-sub-b",
    productId: "fund-hk-001",
    investorId: "bob",
    credentialId: "cred-bob",
    units: "20",
    cashAmount: "200000",
  });
  plane.revokeCredential("cred-bob", "eligibility changed");

  const viewBefore = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" });
  assert.equal(viewBefore.credential.status, "RESTRICTED_EXIT");

  const receipt = plane.redeem({
    id: "tx-controlled-exit",
    idempotencyKey: "idem-controlled-exit",
    productId: "fund-hk-001",
    investorId: "bob",
    credentialId: "cred-bob",
    units: "5",
  });
  assert.equal(receipt.settlementMode, "RESTRICTED_EXIT");
  const viewAfter = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" });
  assert.equal(viewAfter.positionUnits, "15");
  assert.equal(viewAfter.ownTransactions.at(-1).settlementMode, "RESTRICTED_EXIT");
});

test("register timeout creates an exception without moving balances and retry settles a replacement", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-for-exception",
    idempotencyKey: "idem-sub-for-exception",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "100",
    cashAmount: "1000000",
  });
  const bobBefore = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" });

  const failed = plane.simulateRegisterFailure({
    id: "tx-register-timeout",
    productId: "fund-hk-001",
    sellerId: "alice",
    sellerCredentialId: "cred-alice",
    idempotencyKey: "idem-register-timeout",
    buyerId: "bob",
    buyerCredentialId: "cred-bob",
    units: "10",
    pricePerUnit: "10000",
    fee: "100",
    expiresAt: "2026-08-23T12:05:00Z",
  });
  assert.equal(failed.state, "REQUIRES_REVIEW");
  assert.equal(failed.reasonCode, "REGISTER_TIMEOUT");
  const originalPackageHash = failed.evidencePackageHash;

  const bobDuring = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" });
  assert.equal(bobDuring.positionUnits, bobBefore.positionUnits);
  assert.equal(bobDuring.cashBalance, bobBefore.cashBalance);
  const operationsDuring = plane.viewForRole({ role: "operations", productId: "fund-hk-001" });
  assert.equal(operationsDuring.exceptions[0].status, "OPEN");
  assert.equal(operationsDuring.reconciliation.matched, true);
  assert.equal(operationsDuring.reconciliation.overallStatus, "ATTENTION_REQUIRED");

  const proposed = plane.proposeExceptionResolution({
    caseId: failed.exceptionCaseId,
    makerId: "operations-maker",
    decision: "RETRY",
    replacementTransactionId: "tx-register-retry",
  });
  assert.equal(proposed.state, "PENDING_APPROVAL");
  assert.throws(
    () => plane.approveExceptionResolution({ caseId: failed.exceptionCaseId, checkerId: "operations-maker" }),
    (error) => error.code === "MAKER_CHECKER_CONFLICT",
  );
  const resolved = plane.approveExceptionResolution({
    caseId: failed.exceptionCaseId,
    checkerId: "operations-checker",
  });
  assert.equal(resolved.state, "RESOLVED_RETRIED");
  assert.equal(resolved.replacement.state, "SETTLED");
  const bobAfter = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" });
  assert.equal(bobAfter.positionUnits, "10");
  const operationsAfter = plane.viewForRole({ role: "operations", productId: "fund-hk-001" });
  assert.equal(operationsAfter.exceptions[0].replacementTransactionId, "tx-register-retry");
  assert.equal(operationsAfter.reconciliation.cashExpectedCount, 2);
  assert.equal(operationsAfter.reconciliation.cashConfirmedCount, 2);
  assert.equal(operationsAfter.reconciliation.overallStatus, "SANDBOX_CONTROLLED");
  const originalPackage = plane.transactionEvidencePackage("tx-register-timeout");
  assert.equal(originalPackage.packageHash, originalPackageHash);
  const serializedPackage = JSON.stringify(originalPackage);
  assert.equal(serializedPackage.includes("alice"), false);
  assert.equal(serializedPackage.includes("bob"), false);
  assert.equal(serializedPackage.includes("100000"), false);
});

test("future-effective NAV is visible as pending but cannot price a transaction", () => {
  const { plane, institutions } = setup();
  plane.submitEvidence(
    institutions.admin.signStatement({
      id: "nav-future",
      productId: "fund-hk-001",
      dataType: "nav",
      sourceInstitutionId: "admin",
      trustTier: "A",
      effectiveAt: "2026-08-23T13:00:00Z",
      expiresAt: "2026-08-24T13:00:00Z",
      schemaVersion: "1.0.0",
      payload: { navPerUnit: "20000", currency: "HKD" },
    }),
  );
  const receipt = plane.subscribe({
    id: "tx-before-future-nav",
    idempotencyKey: "idem-before-future-nav",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "1",
    cashAmount: "10000",
  });
  assert.equal(receipt.navEvidenceId, "nav-001");
  const operations = plane.viewForRole({ role: "operations", productId: "fund-hk-001" });
  assert.equal(operations.evidence.find((item) => item.id === "nav-future").status, "PENDING");
});

test("expired credential is displayed accurately and cannot acquire assets", () => {
  const { plane, institutions } = setup();
  plane.registerCredential(
    institutions.kyc.signStatement({
      id: "cred-expired",
      issuerId: "kyc",
      subjectId: "expired-investor",
      productId: "fund-hk-001",
      investorClass: "professional",
      jurisdiction: "HK",
      maxUnits: "1000",
      validFrom: "2025-01-01T00:00:00Z",
      validUntil: "2026-01-01T00:00:00Z",
      revocationHandle: "rev-expired",
    }),
  );
  plane.creditSandboxCash("expired-investor", "HKD", "100000");
  const distributor = plane.viewForRole({ role: "distributor", productId: "fund-hk-001" });
  assert.equal(distributor.credentials.find((item) => item.id === "cred-expired").status, "EXPIRED");
  assert.throws(
    () => plane.subscribe({
      id: "tx-expired-credential",
      idempotencyKey: "idem-expired-credential",
      productId: "fund-hk-001",
      investorId: "expired-investor",
      credentialId: "cred-expired",
      units: "1",
      cashAmount: "10000",
    }),
    (error) => error.code === "CREDENTIAL_TIME",
  );
});

test("NAV evidence with the wrong currency is rejected", () => {
  const { plane, institutions } = setup();
  const wrongCurrency = institutions.admin.signStatement({
    id: "nav-wrong-currency",
    productId: "fund-hk-001",
    dataType: "nav",
    sourceInstitutionId: "admin",
    trustTier: "A",
    effectiveAt: "2026-08-23T01:00:00Z",
    expiresAt: "2026-08-24T01:00:00Z",
    schemaVersion: "1.0.0",
    payload: { navPerUnit: "10000", currency: "USD" },
  });
  assert.throws(
    () => plane.submitEvidence(wrongCurrency),
    (error) => error.code === "EVIDENCE_CURRENCY",
  );
});

test("transfer requires seller credential bound to the seller", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-seller-auth-sub",
    idempotencyKey: "idem-seller-auth-sub",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  assert.throws(
    () => plane.transfer({
      id: "tx-no-seller-credential",
      idempotencyKey: "idem-no-seller-credential",
      productId: "fund-hk-001",
      sellerId: "alice",
      buyerId: "bob",
      buyerCredentialId: "cred-bob",
      units: "1",
      pricePerUnit: "10000",
      expiresAt: "2026-08-23T12:05:00Z",
    }),
    (error) => error.code === "UNKNOWN_CREDENTIAL",
  );
  assert.equal(plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "alice" }).positionUnits, "10");
  assert.equal(plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" }).positionUnits, "0");
});

test("self transfer is rejected before any cash or asset mutation", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-self-sub",
    idempotencyKey: "idem-self-sub",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  const before = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "alice" });
  assert.throws(
    () => plane.transfer({
      id: "tx-self",
      idempotencyKey: "idem-self",
      productId: "fund-hk-001",
      sellerId: "alice",
      sellerCredentialId: "cred-alice",
      buyerId: "alice",
      buyerCredentialId: "cred-alice",
      units: "1",
      pricePerUnit: "10000",
      expiresAt: "2026-08-23T12:05:00Z",
    }),
    (error) => error.code === "SELF_TRANSFER",
  );
  const after = plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "alice" });
  assert.equal(after.positionUnits, before.positionUnits);
  assert.equal(after.cashBalance, before.cashBalance);
});

test("exception retry is revalidated and returns to open when buyer becomes restricted", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-retry-policy-sub",
    idempotencyKey: "idem-retry-policy-sub",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "20",
    cashAmount: "200000",
  });
  const failed = plane.simulateRegisterFailure({
    id: "tx-retry-policy-failure",
    idempotencyKey: "idem-retry-policy-failure",
    productId: "fund-hk-001",
    sellerId: "alice",
    sellerCredentialId: "cred-alice",
    buyerId: "bob",
    buyerCredentialId: "cred-bob",
    units: "5",
    pricePerUnit: "10000",
    expiresAt: "2026-08-23T12:05:00Z",
  });
  plane.proposeExceptionResolution({
    caseId: failed.exceptionCaseId,
    makerId: "maker-1",
    decision: "RETRY",
    replacementTransactionId: "tx-retry-policy-replacement",
  });
  plane.revokeCredential("cred-bob", "eligibility changed during review");
  assert.throws(
    () => plane.approveExceptionResolution({ caseId: failed.exceptionCaseId, checkerId: "checker-1" }),
    (error) => error.code === "CREDENTIAL_REVOKED",
  );
  const operations = plane.viewForRole({ role: "operations", productId: "fund-hk-001" });
  assert.equal(operations.exceptions[0].status, "OPEN");
  assert.equal(operations.reconciliation.overallStatus, "ATTENTION_REQUIRED");
  assert.equal(plane.viewForRole({ role: "investor", productId: "fund-hk-001", actorId: "bob" }).positionUnits, "0");
});

test("two-person cancellation closes an exception without creating a replacement", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-cancel-sub",
    idempotencyKey: "idem-cancel-sub",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "20",
    cashAmount: "200000",
  });
  const failed = plane.simulateRegisterFailure({
    id: "tx-cancel-failure",
    idempotencyKey: "idem-cancel-failure",
    productId: "fund-hk-001",
    sellerId: "alice",
    sellerCredentialId: "cred-alice",
    buyerId: "bob",
    buyerCredentialId: "cred-bob",
    units: "5",
    pricePerUnit: "10000",
    expiresAt: "2026-08-23T12:05:00Z",
  });
  plane.proposeExceptionResolution({
    caseId: failed.exceptionCaseId,
    makerId: "maker-cancel",
    decision: "CANCEL",
  });
  const cancelled = plane.approveExceptionResolution({
    caseId: failed.exceptionCaseId,
    checkerId: "checker-cancel",
  });
  assert.equal(cancelled.state, "RESOLVED_CANCELLED");
  const operations = plane.viewForRole({ role: "operations", productId: "fund-hk-001" });
  assert.equal(operations.exceptions[0].replacementTransactionId, null);
  assert.equal(operations.reconciliation.openExceptionCount, 0);
  assert.equal(operations.transactionSummary.find((item) => item.id === "tx-cancel-failure").state, "CANCELLED");
});

test("price outside configured NAV band is rejected", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-1",
    idempotencyKey: "idem-sub-1",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "100",
    cashAmount: "1000000",
  });
  assert.throws(
    () =>
      plane.transfer({
        id: "tx-transfer-price",
        idempotencyKey: "idem-transfer-price",
        productId: "fund-hk-001",
        sellerId: "alice",
        sellerCredentialId: "cred-alice",
        buyerId: "bob",
        buyerCredentialId: "cred-bob",
        units: "20",
        pricePerUnit: "10500",
        expiresAt: "2026-08-23T12:05:00Z",
      }),
    (error) => error.code === "PRICE_DEVIATION",
  );
});

test("tampering with a signed credential is rejected", () => {
  const { plane, institutions } = setup();
  const valid = institutions.kyc.signStatement({
    id: "cred-mallory",
    issuerId: "kyc",
    subjectId: "mallory",
    productId: "fund-hk-001",
    investorClass: "retail",
    jurisdiction: "HK",
    maxUnits: "1",
    validFrom: "2026-08-01T00:00:00Z",
    validUntil: "2027-08-01T00:00:00Z",
    revocationHandle: "rev-mallory",
  });
  assert.throws(
    () => plane.registerCredential({ ...valid, investorClass: "professional", maxUnits: "1000" }),
    (error) => error.code === "INVALID_SIGNATURE",
  );
});

test("idempotency returns the same receipt and does not double issue", () => {
  const { plane } = setup();
  const input = {
    id: "tx-sub-1",
    idempotencyKey: "idem-sub-1",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "100",
    cashAmount: "1000000",
  };
  const first = plane.subscribe(input);
  const second = plane.subscribe(input);
  assert.deepEqual(second, first);
  assert.equal(plane.reconcile("fund-hk-001").confidentialAssetUnits, "100");
});

test("same idempotency key cannot be reused for a different request", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-1",
    idempotencyKey: "idem-conflict",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  assert.throws(
    () =>
      plane.subscribe({
        id: "tx-sub-2",
        idempotencyKey: "idem-conflict",
        productId: "fund-hk-001",
        investorId: "alice",
        credentialId: "cred-alice",
        units: "20",
        cashAmount: "200000",
      }),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
  assert.equal(plane.reconcile("fund-hk-001").confidentialAssetUnits, "10");
});

test("duplicate transaction id is rejected before balances change", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-same",
    idempotencyKey: "idem-first",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  assert.throws(
    () =>
      plane.subscribe({
        id: "tx-same",
        idempotencyKey: "idem-second",
        productId: "fund-hk-001",
        investorId: "alice",
        credentialId: "cred-alice",
        units: "20",
        cashAmount: "200000",
      }),
    (error) => error.code === "DUPLICATE_TRANSACTION",
  );
  assert.equal(plane.reconcile("fund-hk-001").confidentialAssetUnits, "10");
});

test("paused product rejects subscription", () => {
  const { plane } = setup();
  plane.pauseProduct("fund-hk-001", "sandbox control test");
  assert.throws(
    () =>
      plane.subscribe({
        id: "tx-paused",
        idempotencyKey: "idem-paused",
        productId: "fund-hk-001",
        investorId: "alice",
        credentialId: "cred-alice",
        units: "10",
        cashAmount: "100000",
      }),
    (error) => error.code === "PRODUCT_NOT_ACTIVE",
  );
});

test("holding limit is enforced before subscription", () => {
  const { plane } = setup();
  assert.throws(
    () =>
      plane.subscribe({
        id: "tx-limit",
        idempotencyKey: "idem-limit",
        productId: "fund-hk-001",
        investorId: "alice",
        credentialId: "cred-alice",
        units: "1001",
        cashAmount: "10010000",
      }),
    (error) => error.code === "HOLDING_LIMIT",
  );
});

test("expired transfer intent is rejected", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-sub-1",
    idempotencyKey: "idem-sub-1",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  assert.throws(
    () =>
      plane.transfer({
        id: "tx-expired",
        idempotencyKey: "idem-expired",
        productId: "fund-hk-001",
        sellerId: "alice",
        sellerCredentialId: "cred-alice",
        buyerId: "bob",
        buyerCredentialId: "cred-bob",
        units: "1",
        pricePerUnit: "10000",
        expiresAt: "2026-08-23T11:59:59Z",
      }),
    (error) => error.code === "TRANSACTION_EXPIRED",
  );
});

test("insufficient cash rejects subscription without issuing units", () => {
  const { plane } = setup({ cashAmount: "99999" });
  assert.throws(
    () =>
      plane.subscribe({
        id: "tx-no-cash",
        idempotencyKey: "idem-no-cash",
        productId: "fund-hk-001",
        investorId: "alice",
        credentialId: "cred-alice",
        units: "10",
        cashAmount: "100000",
      }),
    (error) => error.code === "INSUFFICIENT_CASH",
  );
  assert.equal(plane.reconcile("fund-hk-001").confidentialAssetUnits, "0");
});

test("tampered NAV evidence is rejected", () => {
  const { plane, institutions } = setup();
  const signed = institutions.admin.signStatement({
    id: "nav-tampered",
    productId: "fund-hk-001",
    dataType: "nav",
    sourceInstitutionId: "admin",
    trustTier: "A",
    effectiveAt: "2026-08-23T01:00:00Z",
    expiresAt: "2026-08-24T01:00:00Z",
    schemaVersion: "1.0.0",
    payload: { navPerUnit: "10000", currency: "HKD" },
  });
  assert.throws(
    () => plane.submitEvidence({ ...signed, payload: { ...signed.payload, navPerUnit: "1" } }),
    (error) => error.code === "INVALID_SIGNATURE",
  );
});

test("issuer view omits investor balances and transaction economics", () => {
  const { plane } = setup();
  plane.subscribe({
    id: "tx-private",
    idempotencyKey: "idem-private",
    productId: "fund-hk-001",
    investorId: "alice",
    credentialId: "cred-alice",
    units: "10",
    cashAmount: "100000",
  });
  const view = plane.viewForRole({ role: "issuer", productId: "fund-hk-001" });
  const serialized = JSON.stringify(view);
  assert.equal(serialized.includes("cashBalance"), false);
  assert.equal(serialized.includes("pricePerUnit"), false);
  assert.equal(serialized.includes("alice"), false);
});

test("supervisor metadata view redacts cash amounts and subject identifiers", () => {
  const { plane } = setup();
  const view = plane.viewForRole({ role: "supervisor", productId: "fund-hk-001" });
  const serialized = JSON.stringify(view.auditEvents);
  assert.equal(serialized.includes("10000000"), false);
  assert.equal(serialized.includes("alice"), false);
  assert.equal(serialized.includes("bob"), false);
  assert.equal(view.disclosureMode, "SANDBOX_METADATA_ONLY");
});
