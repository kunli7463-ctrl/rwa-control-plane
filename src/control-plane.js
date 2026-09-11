import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";

const REQUIRED_PRODUCT_ROLES = [
  "issuer",
  "distributor",
  "credential_issuer",
  "fund_administrator",
  "custodian",
  "transfer_agent",
  "cash_provider",
];

const EVIDENCE_ROLE = {
  nav: "fund_administrator",
  custody_balance: "custodian",
  legal_register: "transfer_agent",
  cash_state: "cash_provider",
};

function invariant(condition, code, message) {
  if (!condition) {
    const error = new Error(message);
    error.code = code;
    throw error;
  }
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function unsigned(statement) {
  const { signature: _signature, ...body } = statement;
  return body;
}

function toNonNegativeInteger(value, field) {
  const parsed = BigInt(value);
  invariant(parsed >= 0n, "INVALID_AMOUNT", `${field} must be non-negative`);
  return parsed;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function createSandboxInstitution({ id, roles }) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    institution: {
      id,
      roles: [...roles],
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
      sandbox: true,
    },
    signStatement(statement) {
      const body = unsigned(statement);
      return {
        ...body,
        signature: sign(null, Buffer.from(canonicalize(body)), privateKey).toString("base64"),
      };
    },
  };
}

export class ControlPlane {
  constructor({ now = () => new Date() } = {}) {
    this.now = now;
    this.institutions = new Map();
    this.products = new Map();
    this.credentials = new Map();
    this.credentialRestrictions = new Map();
    this.evidence = new Map();
    this.transactions = new Map();
    this.cashSettlements = new Map();
    this.exceptionCases = new Map();
    this.idempotency = new Map();
    this.cashBalances = new Map();
    this.assetBalances = new Map();
    this.legalRegister = new Map();
    this.events = [];
  }

  registerInstitution(institution) {
    invariant(!this.institutions.has(institution.id), "DUPLICATE_INSTITUTION", "institution already exists");
    invariant(Array.isArray(institution.roles) && institution.roles.length > 0, "INVALID_ROLES", "roles required");
    this.institutions.set(institution.id, structuredClone(institution));
    this.#record("institution.registered", { institutionId: institution.id, roles: institution.roles });
  }

  createProduct({ id, name, jurisdiction, issuerId, roleAssignments, rules }) {
    invariant(!this.products.has(id), "DUPLICATE_PRODUCT", "product already exists");
    invariant(jurisdiction === "HK", "UNSUPPORTED_JURISDICTION", "sandbox currently supports HK only");
    invariant(this.#hasRole(issuerId, "issuer"), "UNAUTHORIZED_ISSUER", "issuer role required");
    invariant(
      rules?.currency
        && Array.isArray(rules.allowedInvestorClasses)
        && rules.allowedInvestorClasses.length > 0
        && Array.isArray(rules.allowedJurisdictions)
        && rules.allowedJurisdictions.length > 0,
      "INVALID_RULES",
      "product rules incomplete",
    );
    invariant(
      Number.isInteger(rules.maxPriceDeviationBps)
        && rules.maxPriceDeviationBps >= 0
        && rules.maxPriceDeviationBps <= 10_000,
      "INVALID_RULES",
      "price deviation must be an integer between 0 and 10000 bps",
    );

    const product = {
      id,
      name,
      jurisdiction,
      issuerId,
      roleAssignments: structuredClone(roleAssignments),
      rules: structuredClone(rules),
      ruleVersion: 1,
      status: "DRAFT",
      createdAt: this.now().toISOString(),
    };
    this.products.set(id, product);
    this.#record("product.created", { productId: id, issuerId, ruleVersion: 1 });
    return structuredClone(product);
  }

  activateProduct(productId) {
    const product = this.#product(productId);
    invariant(product.status === "DRAFT" || product.status === "PAUSED", "INVALID_PRODUCT_STATE", "product cannot be activated");
    for (const role of REQUIRED_PRODUCT_ROLES) {
      const institutionId = product.roleAssignments[role];
      invariant(institutionId, "MISSING_ROLE", `missing ${role}`);
      invariant(this.#hasRole(institutionId, role), "INVALID_ROLE_ASSIGNMENT", `${institutionId} lacks ${role}`);
    }
    product.status = "ACTIVE";
    this.#record("product.activated", { productId, ruleVersion: product.ruleVersion });
  }

  pauseProduct(productId, reason) {
    const product = this.#product(productId);
    invariant(product.status === "ACTIVE", "INVALID_PRODUCT_STATE", "only active product can be paused");
    product.status = "PAUSED";
    this.#record("product.paused", { productId, reason });
  }

  registerCredential(credential) {
    const product = this.#product(credential.productId);
    invariant(
      credential.issuerId === product.roleAssignments.credential_issuer,
      "UNAUTHORIZED_CREDENTIAL_ISSUER",
      "credential issuer is not assigned to product",
    );
    invariant(this.#verifyStatement(credential), "INVALID_SIGNATURE", "credential signature invalid");
    invariant(!this.credentials.has(credential.id), "DUPLICATE_CREDENTIAL", "credential already exists");
    invariant(
      Number.isFinite(new Date(credential.validFrom).getTime())
        && Number.isFinite(new Date(credential.validUntil).getTime())
        && new Date(credential.validUntil) > new Date(credential.validFrom),
      "INVALID_CREDENTIAL_TIME",
      "credential validity window invalid",
    );
    invariant(toNonNegativeInteger(credential.maxUnits, "maxUnits") > 0n, "INVALID_CREDENTIAL_LIMIT", "maxUnits must be positive");
    this.credentials.set(credential.id, structuredClone(credential));
    this.#record("credential.registered", {
      credentialId: credential.id,
      productId: credential.productId,
      subjectId: credential.subjectId,
    });
  }

  revokeCredential(credentialId, reason) {
    invariant(this.credentials.has(credentialId), "UNKNOWN_CREDENTIAL", "credential not found");
    invariant(!this.credentialRestrictions.has(credentialId), "CREDENTIAL_ALREADY_RESTRICTED", "credential already restricted");
    this.credentialRestrictions.set(credentialId, {
      status: "RESTRICTED_EXIT",
      reason,
      effectiveAt: this.now().toISOString(),
    });
    this.#record("credential.restricted", { credentialId, reason, status: "RESTRICTED_EXIT" });
  }

  submitEvidence(envelope) {
    const product = this.#product(envelope.productId);
    const requiredRole = EVIDENCE_ROLE[envelope.dataType];
    invariant(requiredRole, "UNSUPPORTED_EVIDENCE", "unsupported evidence type");
    invariant(
      envelope.sourceInstitutionId === product.roleAssignments[requiredRole],
      "UNAUTHORIZED_EVIDENCE_SOURCE",
      `evidence must be signed by assigned ${requiredRole}`,
    );
    invariant(this.#verifyStatement(envelope), "INVALID_SIGNATURE", "evidence signature invalid");
    const effectiveAt = new Date(envelope.effectiveAt);
    const expiresAt = new Date(envelope.expiresAt);
    invariant(
      Number.isFinite(effectiveAt.getTime())
        && Number.isFinite(expiresAt.getTime())
        && expiresAt > effectiveAt,
      "INVALID_EVIDENCE_TIME",
      "evidence expiry invalid",
    );
    if (envelope.dataType === "nav") {
      invariant(envelope.payload?.currency === product.rules.currency, "EVIDENCE_CURRENCY", "NAV currency does not match product");
      invariant(toNonNegativeInteger(envelope.payload?.navPerUnit, "navPerUnit") > 0n, "INVALID_NAV", "NAV must be positive");
    }
    invariant(!this.evidence.has(envelope.id), "DUPLICATE_EVIDENCE", "evidence already exists");

    this.evidence.set(envelope.id, { ...structuredClone(envelope), status: "ACTIVE" });
    this.#record("evidence.accepted", {
      evidenceId: envelope.id,
      productId: envelope.productId,
      dataType: envelope.dataType,
    });
  }

  creditSandboxCash(accountId, currency, amount) {
    const key = `${accountId}:${currency}`;
    this.cashBalances.set(key, (this.cashBalances.get(key) ?? 0n) + toNonNegativeInteger(amount, "amount"));
    this.#record("sandbox.cash_credited", { accountId, currency, amount: String(amount) });
  }

  subscribe({ id, idempotencyKey, productId, investorId, credentialId, units, cashAmount }) {
    const request = { id, productId, investorId, credentialId, units, cashAmount };
    return this.#idempotent(idempotencyKey, request, () => this.#runTransactionAttempt({ id, type: "SUBSCRIBE", productId }, (lifecycle) => {
      this.#assertNewTransaction(id);
      const product = this.#activeProduct(productId);
      const unitCount = toNonNegativeInteger(units, "units");
      const amount = toNonNegativeInteger(cashAmount, "cashAmount");
      invariant(unitCount > 0n, "INVALID_AMOUNT", "units must be positive");
      this.#assertEligible({ product, investorId, credentialId, additionalUnits: unitCount });
      const nav = this.#currentEvidence(product, "nav");
      const expected = unitCount * BigInt(nav.payload.navPerUnit);
      invariant(amount === expected, "PRICE_MISMATCH", "subscription amount does not match current NAV");

      const investorCashKey = `${investorId}:${product.rules.currency}`;
      const issuerCashKey = `${product.issuerId}:${product.rules.currency}`;
      invariant((this.cashBalances.get(investorCashKey) ?? 0n) >= amount, "INSUFFICIENT_CASH", "insufficient sandbox cash");

      this.#transition(lifecycle, "POLICY_CHECKED", { id, type: "SUBSCRIBE", productId });
      this.#transition(lifecycle, "CASH_RESERVED", { id, type: "SUBSCRIBE", productId });

      this.cashBalances.set(investorCashKey, this.cashBalances.get(investorCashKey) - amount);
      this.cashBalances.set(issuerCashKey, (this.cashBalances.get(issuerCashKey) ?? 0n) + amount);
      this.#confirmSandboxCash(id, productId);
      this.#transition(lifecycle, "REGISTER_PENDING", { id, type: "SUBSCRIBE", productId });
      this.#addAsset(this.assetBalances, investorId, productId, unitCount);
      this.#addAsset(this.legalRegister, investorId, productId, unitCount);

      const transaction = this.#completeTransaction({
        id,
        type: "SUBSCRIBE",
        productId,
        buyerId: investorId,
        units: unitCount,
        cashAmount: amount,
        ...this.#policySnapshot(product, nav),
        settlementMode: "STANDARD",
        lifecycle,
      });
      this.#record("subscription.settled", { transactionId: id, productId });
      return this.publicReceipt(transaction);
    }));
  }

  transfer({
    id,
    idempotencyKey,
    productId,
    sellerId,
    sellerCredentialId,
    buyerId,
    buyerCredentialId,
    units,
    pricePerUnit,
    fee = "0",
    expiresAt,
  }) {
    const request = {
      id,
      productId,
      sellerId,
      sellerCredentialId,
      buyerId,
      buyerCredentialId,
      units,
      pricePerUnit,
      fee,
      expiresAt,
    };
    return this.#idempotent(idempotencyKey, request, () => this.#runTransactionAttempt({ id, type: "TRANSFER", productId }, (lifecycle) => {
      this.#assertNewTransaction(id);
      const product = this.#activeProduct(productId);
      invariant(new Date(expiresAt) > this.now(), "TRANSACTION_EXPIRED", "transaction intent expired");
      const unitCount = toNonNegativeInteger(units, "units");
      const price = toNonNegativeInteger(pricePerUnit, "pricePerUnit");
      const feeAmount = toNonNegativeInteger(fee, "fee");
      invariant(unitCount > 0n && price > 0n, "INVALID_AMOUNT", "units and price must be positive");
      invariant(sellerId !== buyerId, "SELF_TRANSFER", "seller and buyer must differ");
      invariant(this.#assetOf(this.assetBalances, sellerId, productId) >= unitCount, "INSUFFICIENT_ASSET", "seller balance insufficient");
      this.#assertEligible({ product, investorId: sellerId, credentialId: sellerCredentialId, additionalUnits: 0n });
      this.#assertEligible({ product, investorId: buyerId, credentialId: buyerCredentialId, additionalUnits: unitCount });

      const nav = this.#currentEvidence(product, "nav");
      const navPrice = BigInt(nav.payload.navPerUnit);
      const deviation = price > navPrice ? price - navPrice : navPrice - price;
      invariant(
        deviation * 10_000n <= navPrice * BigInt(product.rules.maxPriceDeviationBps),
        "PRICE_DEVIATION",
        "price exceeds allowed NAV deviation",
      );

      const consideration = unitCount * price;
      const buyerCashKey = `${buyerId}:${product.rules.currency}`;
      const sellerCashKey = `${sellerId}:${product.rules.currency}`;
      const feeCashKey = `${product.issuerId}:${product.rules.currency}`;
      invariant((this.cashBalances.get(buyerCashKey) ?? 0n) >= consideration + feeAmount, "INSUFFICIENT_CASH", "buyer cash insufficient");

      this.#transition(lifecycle, "POLICY_CHECKED", { id, type: "TRANSFER", productId });
      this.#transition(lifecycle, "CASH_RESERVED", { id, type: "TRANSFER", productId });

      this.cashBalances.set(buyerCashKey, this.cashBalances.get(buyerCashKey) - consideration - feeAmount);
      this.cashBalances.set(sellerCashKey, (this.cashBalances.get(sellerCashKey) ?? 0n) + consideration);
      this.cashBalances.set(feeCashKey, (this.cashBalances.get(feeCashKey) ?? 0n) + feeAmount);
      this.#confirmSandboxCash(id, productId);
      this.#transition(lifecycle, "REGISTER_PENDING", { id, type: "TRANSFER", productId });
      this.#addAsset(this.assetBalances, sellerId, productId, -unitCount);
      this.#addAsset(this.assetBalances, buyerId, productId, unitCount);
      this.#addAsset(this.legalRegister, sellerId, productId, -unitCount);
      this.#addAsset(this.legalRegister, buyerId, productId, unitCount);

      const transaction = this.#completeTransaction({
        id,
        type: "TRANSFER",
        productId,
        sellerId,
        buyerId,
        units: unitCount,
        pricePerUnit: price,
        cashAmount: consideration,
        fee: feeAmount,
        expiresAt,
        ...this.#policySnapshot(product, nav),
        settlementMode: "STANDARD",
        lifecycle,
      });
      this.#record("transfer.settled", { transactionId: id, productId });
      return this.publicReceipt(transaction);
    }));
  }

  redeem({ id, idempotencyKey, productId, investorId, credentialId, units }) {
    const request = { id, productId, investorId, credentialId, units };
    return this.#idempotent(idempotencyKey, request, () => this.#runTransactionAttempt({ id, type: "REDEEM", productId }, (lifecycle) => {
      this.#assertNewTransaction(id);
      const product = this.#activeProduct(productId);
      const unitCount = toNonNegativeInteger(units, "units");
      invariant(unitCount > 0n, "INVALID_AMOUNT", "units must be positive");
      const credentialStatus = this.#assertExitAllowed({ product, investorId, credentialId });
      invariant(this.#assetOf(this.assetBalances, investorId, productId) >= unitCount, "INSUFFICIENT_ASSET", "investor balance insufficient");
      const nav = this.#currentEvidence(product, "nav");
      const cashAmount = unitCount * BigInt(nav.payload.navPerUnit);
      const issuerCashKey = `${product.issuerId}:${product.rules.currency}`;
      const investorCashKey = `${investorId}:${product.rules.currency}`;
      invariant((this.cashBalances.get(issuerCashKey) ?? 0n) >= cashAmount, "INSUFFICIENT_REDEMPTION_CASH", "issuer cash insufficient");

      this.#transition(lifecycle, "POLICY_CHECKED", { id, type: "REDEEM", productId });
      this.#transition(lifecycle, "CASH_RESERVED", { id, type: "REDEEM", productId });
      this.#addAsset(this.assetBalances, investorId, productId, -unitCount);
      this.#addAsset(this.legalRegister, investorId, productId, -unitCount);
      this.cashBalances.set(issuerCashKey, this.cashBalances.get(issuerCashKey) - cashAmount);
      this.cashBalances.set(investorCashKey, (this.cashBalances.get(investorCashKey) ?? 0n) + cashAmount);
      this.#confirmSandboxCash(id, productId);
      this.#transition(lifecycle, "REGISTER_PENDING", { id, type: "REDEEM", productId });

      const transaction = this.#completeTransaction({
        id,
        type: "REDEEM",
        productId,
        sellerId: investorId,
        units: unitCount,
        cashAmount,
        ...this.#policySnapshot(product, nav),
        settlementMode: credentialStatus === "RESTRICTED_EXIT" ? "RESTRICTED_EXIT" : "STANDARD",
        lifecycle,
      });
      this.#record(
        credentialStatus === "RESTRICTED_EXIT" ? "redemption.restricted_exit_settled" : "redemption.settled",
        { transactionId: id, productId },
      );
      return this.publicReceipt(transaction);
    }));
  }

  simulateRegisterFailure({
    id,
    idempotencyKey,
    productId,
    sellerId,
    sellerCredentialId,
    buyerId,
    buyerCredentialId,
    units,
    pricePerUnit,
    fee = "0",
    expiresAt,
  }) {
    const request = { id, productId, sellerId, sellerCredentialId, buyerId, buyerCredentialId, units, pricePerUnit, fee, expiresAt };
    return this.#idempotent(idempotencyKey, request, () => {
      const lifecycle = [];
      this.#transition(lifecycle, "REQUESTED", { id, type: "TRANSFER", productId });
      try {
      this.#assertNewTransaction(id);
      const product = this.#activeProduct(productId);
      invariant(new Date(expiresAt) > this.now(), "TRANSACTION_EXPIRED", "transaction intent expired");
      const unitCount = toNonNegativeInteger(units, "units");
      const price = toNonNegativeInteger(pricePerUnit, "pricePerUnit");
      const feeAmount = toNonNegativeInteger(fee, "fee");
      invariant(unitCount > 0n && price > 0n, "INVALID_AMOUNT", "units and price must be positive");
      invariant(sellerId !== buyerId, "SELF_TRANSFER", "seller and buyer must differ");
      invariant(this.#assetOf(this.assetBalances, sellerId, productId) >= unitCount, "INSUFFICIENT_ASSET", "seller balance insufficient");
      this.#assertEligible({ product, investorId: sellerId, credentialId: sellerCredentialId, additionalUnits: 0n });
      this.#assertEligible({ product, investorId: buyerId, credentialId: buyerCredentialId, additionalUnits: unitCount });

      const nav = this.#currentEvidence(product, "nav");
      const navPrice = BigInt(nav.payload.navPerUnit);
      const deviation = price > navPrice ? price - navPrice : navPrice - price;
      invariant(
        deviation * 10_000n <= navPrice * BigInt(product.rules.maxPriceDeviationBps),
        "PRICE_DEVIATION",
        "price exceeds allowed NAV deviation",
      );
      const consideration = unitCount * price;
      const buyerCashKey = `${buyerId}:${product.rules.currency}`;
      invariant((this.cashBalances.get(buyerCashKey) ?? 0n) >= consideration + feeAmount, "INSUFFICIENT_CASH", "buyer cash insufficient");

      this.#transition(lifecycle, "POLICY_CHECKED", { id, type: "TRANSFER", productId });
      this.#transition(lifecycle, "CASH_RESERVED", { id, type: "TRANSFER", productId });
      this.#transition(lifecycle, "REGISTER_FAILED", { id, type: "TRANSFER", productId });
      this.cashSettlements.set(id, {
        transactionId: id,
        productId,
        state: "RELEASED",
        source: "SANDBOX_CASH_JOURNAL",
        confirmedAt: this.now().toISOString(),
      });
      this.#record("cash.reservation_released", { transactionId: id, productId, state: "RELEASED" });
      this.#transition(lifecycle, "REQUIRES_REVIEW", { id, type: "TRANSFER", productId });

      const transaction = this.#storeExceptionTransaction({
        id,
        type: "TRANSFER",
        productId,
        sellerId,
        buyerId,
        units: unitCount,
        pricePerUnit: price,
        cashAmount: consideration,
        fee: feeAmount,
        expiresAt,
        ...this.#policySnapshot(product, nav),
        settlementMode: "EXCEPTION_REVIEW",
        lifecycle,
      });
      const exceptionCase = {
        id: `case-${id}`,
        productId,
        transactionId: id,
        status: "OPEN",
        failureStage: "REGISTER_PENDING",
        reasonCode: "REGISTER_TIMEOUT",
        assignedRole: "operations",
        openedAt: this.now().toISOString(),
        resolvedAt: null,
        replacementTransactionId: null,
        proposal: null,
        retryPayload: {
          productId,
          sellerId,
          sellerCredentialId,
          buyerId,
          buyerCredentialId,
          units: unitCount.toString(),
          pricePerUnit: price.toString(),
          fee: feeAmount.toString(),
          expiresAt,
        },
      };
      this.exceptionCases.set(exceptionCase.id, exceptionCase);
      this.#record("exception.opened", {
        productId,
        transactionId: id,
        state: "OPEN",
        reasonCode: exceptionCase.reasonCode,
      });
      return {
        ...this.publicReceipt(transaction),
        exceptionCaseId: exceptionCase.id,
        reasonCode: exceptionCase.reasonCode,
      };
    } catch (error) {
      this.#record("transaction.rejected", {
        transactionId: id,
        productId,
        transactionType: "TRANSFER",
        state: "REJECTED",
        reasonCode: error.code ?? "REQUEST_FAILED",
      });
      throw error;
      }
    });
  }

  proposeExceptionResolution({ caseId, makerId, decision, replacementTransactionId = null }) {
    const exceptionCase = this.exceptionCases.get(caseId);
    invariant(exceptionCase, "UNKNOWN_EXCEPTION", "exception case not found");
    invariant(exceptionCase.status === "OPEN", "EXCEPTION_NOT_OPEN", "exception case is not open for proposal");
    invariant(makerId, "MISSING_MAKER", "maker identity required");
    invariant(decision === "RETRY" || decision === "CANCEL", "INVALID_DECISION", "decision must be RETRY or CANCEL");
    invariant(decision !== "RETRY" || replacementTransactionId, "MISSING_REPLACEMENT_ID", "replacement transaction id required");
    exceptionCase.status = "PENDING_APPROVAL";
    const original = this.transactions.get(exceptionCase.transactionId);
    original.state = "PENDING_APPROVAL";
    this.#transition(original.lifecycle, "REVIEW_PROPOSED", {
      id: original.id,
      type: original.type,
      productId: original.productId,
    });
    exceptionCase.proposal = {
      decision,
      replacementTransactionId,
      makerId,
      proposedAt: this.now().toISOString(),
    };
    this.#record("exception.resolution_proposed", {
      productId: exceptionCase.productId,
      transactionId: exceptionCase.transactionId,
      state: "PENDING_APPROVAL",
    });
    return {
      caseId,
      state: exceptionCase.status,
      decision,
      replacementTransactionId,
      makerId,
    };
  }

  approveExceptionResolution({ caseId, checkerId }) {
    const exceptionCase = this.exceptionCases.get(caseId);
    invariant(exceptionCase, "UNKNOWN_EXCEPTION", "exception case not found");
    invariant(exceptionCase.status === "PENDING_APPROVAL", "EXCEPTION_NOT_PENDING_APPROVAL", "exception case has no pending proposal");
    invariant(checkerId, "MISSING_CHECKER", "checker identity required");
    invariant(checkerId !== exceptionCase.proposal.makerId, "MAKER_CHECKER_CONFLICT", "maker and checker must be different people");
    const original = this.transactions.get(exceptionCase.transactionId);
    const { decision, replacementTransactionId } = exceptionCase.proposal;
    this.#transition(original.lifecycle, "REVIEW_APPROVED", {
      id: original.id,
      type: original.type,
      productId: original.productId,
    });

    if (decision === "CANCEL") {
      original.state = "CANCELLED";
      this.#transition(original.lifecycle, "CANCELLED", {
        id: original.id,
        type: original.type,
        productId: original.productId,
      });
      exceptionCase.status = "RESOLVED_CANCELLED";
    } else {
      const retry = exceptionCase.retryPayload;
      let receipt;
      try {
        receipt = this.transfer({
          id: replacementTransactionId,
          idempotencyKey: `exception-retry:${caseId}:${replacementTransactionId}`,
          ...retry,
        });
      } catch (error) {
        exceptionCase.status = "OPEN";
        exceptionCase.proposal = null;
        original.state = "REQUIRES_REVIEW";
        this.#transition(original.lifecycle, "RETRY_BLOCKED", {
          id: original.id,
          type: original.type,
          productId: original.productId,
        });
        this.#record("exception.retry_blocked", {
          productId: exceptionCase.productId,
          transactionId: exceptionCase.transactionId,
          state: "OPEN",
          reasonCode: error.code ?? "REQUEST_FAILED",
        });
        throw error;
      }
      original.state = "REPLACED";
      this.#transition(original.lifecycle, "REPLACED", {
        id: original.id,
        type: original.type,
        productId: original.productId,
      });
      exceptionCase.status = "RESOLVED_RETRIED";
      exceptionCase.replacementTransactionId = replacementTransactionId;
      exceptionCase.resolvedAt = this.now().toISOString();
      exceptionCase.checkedBy = checkerId;
      this.#record("exception.resolved", {
        productId: exceptionCase.productId,
        transactionId: exceptionCase.transactionId,
        state: exceptionCase.status,
      });
      return {
        caseId,
        state: exceptionCase.status,
        makerId: exceptionCase.proposal.makerId,
        checkerId,
        replacement: receipt,
      };
    }

    exceptionCase.resolvedAt = this.now().toISOString();
    exceptionCase.checkedBy = checkerId;
    this.#record("exception.resolved", {
      productId: exceptionCase.productId,
      transactionId: exceptionCase.transactionId,
      state: exceptionCase.status,
    });
    return {
      caseId,
      state: exceptionCase.status,
      makerId: exceptionCase.proposal.makerId,
      checkerId,
    };
  }

  reconcile(productId) {
    this.#product(productId);
    const asset = this.#totalForProduct(this.assetBalances, productId);
    const register = this.#totalForProduct(this.legalRegister, productId);
    const settledTransactions = [...this.transactions.values()].filter(
      (item) => item.productId === productId && item.state === "SETTLED",
    );
    const confirmedCashSettlements = settledTransactions.filter(
      (item) => this.cashSettlements.get(item.id)?.state === "CONFIRMED",
    );
    const openExceptionCount = [...this.exceptionCases.values()].filter(
      (item) => item.productId === productId && !item.status.startsWith("RESOLVED_"),
    ).length;
    const assetRegisterMatched = asset === register;
    const cashConfirmed = confirmedCashSettlements.length === settledTransactions.length;
    const accountingControlsMatched = assetRegisterMatched && cashConfirmed;
    return {
      productId,
      confidentialAssetUnits: asset.toString(),
      legalRegisterUnits: register.toString(),
      assetRegisterMatched,
      cashExpectedCount: settledTransactions.length,
      cashConfirmedCount: confirmedCashSettlements.length,
      cashControlMode: "SANDBOX_JOURNAL_NOT_BANK_RECEIPT",
      cashConfirmed,
      openExceptionCount,
      matched: accountingControlsMatched,
      overallStatus: !accountingControlsMatched
        ? "RECONCILIATION_EXCEPTION"
        : openExceptionCount > 0
          ? "ATTENTION_REQUIRED"
          : "SANDBOX_CONTROLLED",
      checkedAt: this.now().toISOString(),
    };
  }

  viewForRole({ role, productId, actorId = null }) {
    const product = this.#product(productId);
    const reconciliation = this.reconcile(productId);
    const evidence = [...this.evidence.values()]
      .filter((item) => item.productId === productId)
      .map((item) => ({
        id: item.id,
        dataType: item.dataType,
        sourceInstitutionId: item.sourceInstitutionId,
        trustTier: item.trustTier,
        effectiveAt: item.effectiveAt,
        expiresAt: item.expiresAt,
        status: new Date(item.effectiveAt) > this.now()
          ? "PENDING"
          : new Date(item.expiresAt) > this.now()
            ? item.status
            : "EXPIRED",
      }));
    const transactionSummary = [...this.transactions.values()]
      .filter((item) => item.productId === productId)
      .map((item) => ({
        id: item.id,
        type: item.type,
        state: item.state,
        settledAt: item.settledAt,
        settlementMode: item.settlementMode,
        evidencePackageHash: this.transactionEvidencePackage(item.id).packageHash,
      }));
    const exceptions = [...this.exceptionCases.values()]
      .filter((item) => item.productId === productId)
      .map((item) => ({
        id: item.id,
        transactionId: item.transactionId,
        status: item.status,
        failureStage: item.failureStage,
        reasonCode: item.reasonCode,
        assignedRole: item.assignedRole,
        openedAt: item.openedAt,
        resolvedAt: item.resolvedAt,
        replacementTransactionId: item.replacementTransactionId,
        proposedDecision: item.proposal?.decision ?? null,
        proposedBy: item.proposal?.makerId ?? null,
        checkedBy: item.checkedBy ?? null,
      }));

    const base = {
      role,
      sandbox: true,
      generatedAt: this.now().toISOString(),
      product: {
        id: product.id,
        name: product.name,
        jurisdiction: product.jurisdiction,
        status: product.status,
        ruleVersion: product.ruleVersion,
        rules: structuredClone(product.rules),
      },
    };

    if (role === "issuer") {
      return {
        ...base,
        roleAssignments: structuredClone(product.roleAssignments),
        evidence,
        reconciliation,
        transactionSummary,
      };
    }

    if (role === "distributor") {
      const credentials = [...this.credentials.values()]
        .filter((item) => item.productId === productId)
        .map((item) => ({
          id: item.id,
          subjectId: item.subjectId,
          investorClass: item.investorClass,
          jurisdiction: item.jurisdiction,
          maxUnits: item.maxUnits,
          validUntil: item.validUntil,
          status: this.#credentialStatus(item.id),
          restriction: this.credentialRestrictions.get(item.id) ?? null,
        }));
      return { ...base, credentials };
    }

    if (role === "investor") {
      invariant(actorId, "MISSING_ACTOR", "investor actor required");
      const ownTransactions = [...this.transactions.values()]
        .filter((item) => item.productId === productId && (item.buyerId === actorId || item.sellerId === actorId))
        .map((item) => ({
          id: item.id,
          type: item.type,
          state: item.state,
          units: item.units,
          cashAmount: item.cashAmount,
          fee: item.fee ?? "0",
          settlementMode: item.settlementMode,
          settledAt: item.settledAt,
        }));
      const credential = [...this.credentials.values()].find(
        (item) => item.productId === productId && item.subjectId === actorId,
      );
      return {
        ...base,
        actorId,
        positionUnits: this.#assetOf(this.assetBalances, actorId, productId).toString(),
        cashBalance: (this.cashBalances.get(`${actorId}:${product.rules.currency}`) ?? 0n).toString(),
        credential: credential
          ? {
              id: credential.id,
              investorClass: credential.investorClass,
              jurisdiction: credential.jurisdiction,
              maxUnits: credential.maxUnits,
              validUntil: credential.validUntil,
              status: this.#credentialStatus(credential.id),
              restriction: this.credentialRestrictions.get(credential.id) ?? null,
            }
          : null,
        ownTransactions,
      };
    }

    if (role === "broker") {
      return {
        ...base,
        transactions: [...this.transactions.values()]
          .filter((item) => item.productId === productId)
          .map((item) => ({
            id: item.id,
            type: item.type,
            sellerId: item.sellerId ?? null,
            buyerId: item.buyerId ?? null,
            units: item.units,
            pricePerUnit: item.pricePerUnit ?? null,
            fee: item.fee ?? "0",
            state: item.state,
            settledAt: item.settledAt,
            navEvidenceId: item.navEvidenceId,
            ruleVersion: item.ruleVersion,
            policySnapshotHash: item.policySnapshotHash,
            settlementMode: item.settlementMode,
            lifecycle: structuredClone(item.lifecycle),
          })),
      };
    }

    if (role === "operations") {
      return { ...base, evidence, reconciliation, transactionSummary, exceptions };
    }

    if (role === "supervisor") {
      const auditEvents = this.events.map((event) => ({
        sequence: event.sequence,
        type: event.type,
        at: event.at,
        productId: event.productId ?? null,
        transactionId: event.transactionId ?? null,
        transactionType: event.transactionType ?? null,
        state: event.state ?? null,
        reasonCode: event.reasonCode ?? null,
        evidenceId: event.evidenceId ?? null,
        credentialRef: event.credentialId ? sha256(event.credentialId).slice(0, 16) : null,
      }));
      return {
        ...base,
        evidence,
        reconciliation,
        auditEvents,
        disclosureMode: "SANDBOX_METADATA_ONLY",
      };
    }

    invariant(false, "UNKNOWN_ROLE", "unsupported demo role");
  }

  publicReceipt(transaction) {
    return {
      transactionId: transaction.id,
      productId: transaction.productId,
      type: transaction.type,
      state: transaction.state,
      settledAt: transaction.settledAt,
      navEvidenceId: transaction.navEvidenceId,
      ruleVersion: transaction.ruleVersion,
      settlementMode: transaction.settlementMode,
      lifecycle: transaction.lifecycle.map((item) => item.state),
      evidencePackageHash: this.transactionEvidencePackage(transaction.id).packageHash,
      sandboxCommitment: transaction.sandboxCommitment,
      proofSystem: "SANDBOX_NO_ZK_PROOF",
    };
  }

  transactionEvidencePackage(transactionId) {
    const transaction = this.transactions.get(transactionId);
    invariant(transaction, "UNKNOWN_TRANSACTION", "transaction not found");
    const cashControl = this.cashSettlements.get(transactionId) ?? null;
    const immutableCore = {
      schemaVersion: "1.0.0-sandbox",
      transaction: {
        id: transaction.id,
        productId: transaction.productId,
        type: transaction.type,
        stateAtCreation: transaction.settledAt ? "SETTLED" : "REQUIRES_REVIEW",
        ruleVersion: transaction.ruleVersion,
        navEvidenceId: transaction.navEvidenceId,
        navEffectiveAt: transaction.navEffectiveAt,
        navExpiresAt: transaction.navExpiresAt,
        navSchemaVersion: transaction.navSchemaVersion,
        policySnapshotHash: transaction.policySnapshotHash,
        settlementMode: transaction.settlementMode,
        lifecycleAtCreation: transaction.lifecycle
          .filter((item) => [
            "REQUESTED",
            "POLICY_CHECKED",
            "CASH_RESERVED",
            "REGISTER_PENDING",
            "REGISTER_FAILED",
            "REQUIRES_REVIEW",
            "SETTLED",
          ].includes(item.state))
          .map((item) => ({ state: item.state, at: item.at })),
      },
      cashControl: cashControl
        ? { state: cashControl.state, source: cashControl.source, confirmedAt: cashControl.confirmedAt }
        : null,
      disclosure: "NO_PARTIES_NO_AMOUNTS_NO_PRICES",
      proofSystem: "SANDBOX_NO_ZK_PROOF",
    };
    return {
      ...structuredClone(immutableCore),
      generatedAt: this.now().toISOString(),
      packageHash: sha256(canonicalize(immutableCore)),
    };
  }

  eventsForAudit() {
    return structuredClone(this.events);
  }

  #assertEligible({ product, investorId, credentialId, additionalUnits }) {
    const credential = this.credentials.get(credentialId);
    invariant(credential, "UNKNOWN_CREDENTIAL", "credential not found");
    const status = this.#credentialStatus(credentialId);
    invariant(status !== "RESTRICTED_EXIT", "CREDENTIAL_REVOKED", "credential revoked");
    invariant(status === "ACTIVE", "CREDENTIAL_TIME", "credential not active");
    invariant(credential.productId === product.id, "CREDENTIAL_SCOPE", "credential not valid for product");
    invariant(credential.subjectId === investorId, "CREDENTIAL_SUBJECT", "credential subject mismatch");
    invariant(this.#verifyStatement(credential), "INVALID_SIGNATURE", "credential signature invalid");
    const now = this.now();
    invariant(new Date(credential.validFrom) <= now && new Date(credential.validUntil) > now, "CREDENTIAL_TIME", "credential not active");
    invariant(product.rules.allowedInvestorClasses.includes(credential.investorClass), "INVESTOR_CLASS", "investor class not allowed");
    invariant(product.rules.allowedJurisdictions.includes(credential.jurisdiction), "INVESTOR_JURISDICTION", "jurisdiction not allowed");
    const projected = this.#assetOf(this.assetBalances, investorId, product.id) + additionalUnits;
    invariant(projected <= BigInt(credential.maxUnits), "HOLDING_LIMIT", "credential holding limit exceeded");
  }

  #assertExitAllowed({ product, investorId, credentialId }) {
    const credential = this.credentials.get(credentialId);
    invariant(credential, "UNKNOWN_CREDENTIAL", "credential not found");
    invariant(credential.productId === product.id, "CREDENTIAL_SCOPE", "credential not valid for product");
    invariant(credential.subjectId === investorId, "CREDENTIAL_SUBJECT", "credential subject mismatch");
    invariant(this.#verifyStatement(credential), "INVALID_SIGNATURE", "credential signature invalid");
    const status = this.#credentialStatus(credentialId);
    invariant(status !== "FROZEN", "CREDENTIAL_FROZEN", "credential is frozen by an authorized control");
    invariant(status === "ACTIVE" || status === "RESTRICTED_EXIT", "EXIT_NOT_ALLOWED", "credential cannot use controlled exit");
    return status;
  }

  #credentialStatus(credentialId) {
    const restriction = this.credentialRestrictions.get(credentialId);
    if (restriction) return restriction.status;
    const credential = this.credentials.get(credentialId);
    if (!credential) return "UNKNOWN";
    if (new Date(credential.validFrom) > this.now()) return "PENDING";
    if (new Date(credential.validUntil) <= this.now()) return "EXPIRED";
    return "ACTIVE";
  }

  #currentEvidence(product, dataType) {
    const candidates = [...this.evidence.values()]
      .filter((item) => item.productId === product.id
        && item.dataType === dataType
        && item.status === "ACTIVE"
        && new Date(item.effectiveAt) <= this.now())
      .sort((a, b) => new Date(b.effectiveAt) - new Date(a.effectiveAt));
    invariant(candidates.length > 0, "MISSING_EVIDENCE", `missing ${dataType} evidence`);
    const evidence = candidates[0];
    invariant(new Date(evidence.expiresAt) > this.now(), "EVIDENCE_EXPIRED", `${dataType} evidence expired`);
    return evidence;
  }

  #policySnapshot(product, nav) {
    const snapshot = {
      ruleVersion: product.ruleVersion,
      rules: structuredClone(product.rules),
      navEvidenceId: nav.id,
      navEffectiveAt: nav.effectiveAt,
      navExpiresAt: nav.expiresAt,
      navSchemaVersion: nav.schemaVersion,
    };
    return {
      ruleVersion: snapshot.ruleVersion,
      navEvidenceId: snapshot.navEvidenceId,
      navEffectiveAt: snapshot.navEffectiveAt,
      navExpiresAt: snapshot.navExpiresAt,
      navSchemaVersion: snapshot.navSchemaVersion,
      policySnapshotHash: sha256(canonicalize(snapshot)),
    };
  }

  #verifyStatement(statement) {
    const institutionId = statement.issuerId ?? statement.sourceInstitutionId;
    const institution = this.institutions.get(institutionId);
    if (!institution || !statement.signature) return false;
    return verify(
      null,
      Buffer.from(canonicalize(unsigned(statement))),
      institution.publicKeyPem,
      Buffer.from(statement.signature, "base64"),
    );
  }

  #completeTransaction(data) {
    invariant(!this.transactions.has(data.id), "DUPLICATE_TRANSACTION", "transaction already exists");
    const { lifecycle, ...transactionData } = data;
    const privateBody = {
      ...transactionData,
      units: data.units.toString(),
      cashAmount: data.cashAmount.toString(),
      ...(data.pricePerUnit === undefined ? {} : { pricePerUnit: data.pricePerUnit.toString() }),
      ...(data.fee === undefined ? {} : { fee: data.fee.toString() }),
    };
    const salt = randomBytes(32).toString("hex");
    const transaction = {
      ...privateBody,
      state: "SETTLED",
      settledAt: this.now().toISOString(),
      lifecycle,
      sandboxCommitment: sha256(`${canonicalize(privateBody)}:${salt}`),
    };
    this.#transition(lifecycle, "SETTLED", { id: data.id, type: data.type, productId: data.productId });
    this.transactions.set(data.id, transaction);
    return transaction;
  }

  #storeExceptionTransaction(data) {
    const { lifecycle, ...transactionData } = data;
    const privateBody = {
      ...transactionData,
      units: data.units.toString(),
      cashAmount: data.cashAmount.toString(),
      pricePerUnit: data.pricePerUnit.toString(),
      fee: data.fee.toString(),
    };
    const transaction = {
      ...privateBody,
      state: "REQUIRES_REVIEW",
      settledAt: null,
      lifecycle,
      sandboxCommitment: sha256(`${canonicalize(privateBody)}:exception`),
    };
    this.transactions.set(data.id, transaction);
    return transaction;
  }

  #runTransactionAttempt({ id, type, productId }, operation) {
    const lifecycle = [];
    this.#transition(lifecycle, "REQUESTED", { id, type, productId });
    try {
      return operation(lifecycle);
    } catch (error) {
      this.#record("transaction.rejected", {
        transactionId: id,
        productId,
        transactionType: type,
        state: "REJECTED",
        reasonCode: error.code ?? "REQUEST_FAILED",
      });
      throw error;
    }
  }

  #transition(lifecycle, state, { id, type, productId }) {
    const transition = { state, at: this.now().toISOString() };
    lifecycle.push(transition);
    this.#record("transaction.state_changed", {
      transactionId: id,
      productId,
      transactionType: type,
      state,
    });
  }

  #confirmSandboxCash(transactionId, productId) {
    this.cashSettlements.set(transactionId, {
      transactionId,
      productId,
      state: "CONFIRMED",
      source: "SANDBOX_CASH_JOURNAL",
      confirmedAt: this.now().toISOString(),
    });
    this.#record("cash.sandbox_confirmed", { transactionId, productId, state: "CONFIRMED" });
  }

  #idempotent(key, request, operation) {
    invariant(key, "MISSING_IDEMPOTENCY_KEY", "idempotency key required");
    const fingerprint = sha256(canonicalize(request));
    if (this.idempotency.has(key)) {
      const previous = this.idempotency.get(key);
      invariant(previous.fingerprint === fingerprint, "IDEMPOTENCY_CONFLICT", "idempotency key reused for different request");
      return structuredClone(previous.result);
    }
    const result = operation();
    this.idempotency.set(key, { fingerprint, result: structuredClone(result) });
    return result;
  }

  #assertNewTransaction(id) {
    invariant(!this.transactions.has(id), "DUPLICATE_TRANSACTION", "transaction already exists");
  }

  #addAsset(ledger, accountId, productId, delta) {
    const key = `${accountId}:${productId}`;
    const next = (ledger.get(key) ?? 0n) + delta;
    invariant(next >= 0n, "NEGATIVE_BALANCE", "ledger balance cannot be negative");
    ledger.set(key, next);
  }

  #assetOf(ledger, accountId, productId) {
    return ledger.get(`${accountId}:${productId}`) ?? 0n;
  }

  #totalForProduct(ledger, productId) {
    let total = 0n;
    for (const [key, value] of ledger) {
      if (key.endsWith(`:${productId}`)) total += value;
    }
    return total;
  }

  #hasRole(institutionId, role) {
    return this.institutions.get(institutionId)?.roles.includes(role) ?? false;
  }

  #product(productId) {
    const product = this.products.get(productId);
    invariant(product, "UNKNOWN_PRODUCT", "product not found");
    return product;
  }

  #activeProduct(productId) {
    const product = this.#product(productId);
    invariant(product.status === "ACTIVE", "PRODUCT_NOT_ACTIVE", "product is not active");
    return product;
  }

  #record(type, payload) {
    this.events.push({ sequence: this.events.length + 1, type, at: this.now().toISOString(), ...payload });
  }
}
