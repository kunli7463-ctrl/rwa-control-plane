import { PostgresStore, sha256Canonical } from "./postgres-store.js";
import { RedactedPayloadCipher } from "../security/envelope-crypto.js";
import { partyIndexFor } from "../security/economic-commitment.js";

const TENANT = "sandbox-hk";
const SANDBOX_RESET_TRIGGER_TABLES = Object.freeze([
  "approval_records", "audit_events", "callback_applications", "callback_effects",
  "callback_evidence_records", "callback_receipts", "external_callback_confirmations",
  "external_incident_approvals", "inbox_consumptions", "ledger_entries", "prover_jobs",
  "register_callback_events", "register_entries", "transaction_economic_commitments",
  "transaction_receipts", "transaction_state_history", "zk_execution_instructions",
  "zk_finalization_proposals", "zk_output_commitments", "zk_proof_receipts",
  "zk_root_publication_attestations", "zk_settlements", "zk_spent_nullifiers",
  "zk_transaction_authorizations",
]);

function fail(condition, code, message) {
  if (condition) return;
  const error = new Error(message);
  error.code = code;
  throw error;
}

function positive(value, field) {
  const parsed = BigInt(value);
  fail(parsed > 0n, "INVALID_AMOUNT", `${field} must be positive`);
  return parsed;
}

function ledgerAccountId(productId, ownerRef, assetCode, accountType) {
  return `ledger:${productId}:${ownerRef}:${assetCode}:${accountType}`;
}

function registerAccountId(productId, ownerRef, assetCode, accountType) {
  return `register:${productId}:${ownerRef}:${assetCode}:${accountType}`;
}

export class DurableWorkflowService {
  constructor(store, {
    now = () => new Date(), tenantId = TENANT, payloadCipher = new RedactedPayloadCipher(), economicCommitter = null,
  } = {}) {
    this.store = store;
    this.now = now;
    this.tenantId = tenantId;
    this.payloadCipher = payloadCipher;
    this.economicCommitter = economicCommitter;
  }

  static async connect(options) {
    const store = await PostgresStore.connect(options);
    return new DurableWorkflowService(store, options);
  }

  async close() {
    await this.store.close();
  }

  async bootstrapFromControlPlane(plane) {
    return this.store.withSerializableTransaction(async (client) => {
      for (const institution of plane.institutions.values()) {
        await client.query(
          `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem)
           VALUES ($1,$1,'HK','ACTIVE',$2)
           ON CONFLICT (id) DO NOTHING`,
          [institution.id, institution.publicKeyPem],
        );
        const saved = await client.query("SELECT public_key_pem FROM rwa.institutions WHERE id=$1", [institution.id]);
        fail(saved.rows[0].public_key_pem === institution.publicKeyPem, "BOOTSTRAP_KEY_MISMATCH", `institution key mismatch: ${institution.id}`);
      }

      for (const product of plane.products.values()) {
        await client.query(
          `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
           ON CONFLICT (id) DO NOTHING`,
          [product.id, product.name, product.jurisdiction, product.issuerId, product.rules.currency,
            product.status, product.ruleVersion, JSON.stringify(product.rules)],
        );
        for (const [role, institutionId] of Object.entries(product.roleAssignments)) {
          await client.query(
            `INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at)
             VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
            [product.id, role, institutionId, product.createdAt],
          );
        }
      }

      for (const evidence of plane.evidence.values()) {
        await client.query(
          `INSERT INTO rwa.evidence_envelopes
           (id,product_id,data_type,source_institution_id,trust_tier,schema_version,effective_at,expires_at,
            payload,payload_hash,signature,status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)
           ON CONFLICT (id) DO NOTHING`,
          [evidence.id, evidence.productId, evidence.dataType, evidence.sourceInstitutionId,
            evidence.trustTier, evidence.schemaVersion, evidence.effectiveAt, evidence.expiresAt,
            JSON.stringify(evidence.payload), sha256Canonical(evidence.payload), evidence.signature, evidence.status],
        );
      }

      for (const credential of plane.credentials.values()) {
        const restriction = plane.credentialRestrictions.get(credential.id);
        await client.query(
          `INSERT INTO rwa.credentials
           (id,product_id,issuer_id,subject_ref,investor_class,jurisdiction,max_units,valid_from,valid_until,
            status,restriction_reason,signed_payload,signature)
           VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12::jsonb,$13)
           ON CONFLICT (id) DO NOTHING`,
          [credential.id, credential.productId, credential.issuerId, credential.subjectId,
            credential.investorClass, credential.jurisdiction, credential.maxUnits, credential.validFrom,
            credential.validUntil, restriction?.status ?? "ACTIVE", restriction?.reason ?? null,
            JSON.stringify(credential), credential.signature],
        );
      }

      for (const product of plane.products.values()) {
        const unitAsset = `UNIT:${product.id}`;
        const owners = new Set([product.issuerId, "EXTERNAL_CASH", "TREASURY"]);
        for (const credential of plane.credentials.values()) {
          if (credential.productId === product.id) owners.add(credential.subjectId);
        }
        for (const owner of owners) {
          if (!new Set(["TREASURY"]).has(owner)) {
            const cashType = owner === product.issuerId ? "ISSUER" : owner === "EXTERNAL_CASH" ? "CASH_CLEARING" : "INVESTOR";
            await this.#ensureLedgerAccount(client, product.id, owner, product.rules.currency, cashType);
          }
          if (owner !== "EXTERNAL_CASH") {
            const unitType = owner === "TREASURY" ? "TREASURY" : "INVESTOR";
            await this.#ensureLedgerAccount(client, product.id, owner, unitAsset, unitType);
            await this.#ensureRegisterAccount(client, product.id, owner, unitAsset, unitType);
          }
        }
        await this.#ensureLedgerAccount(client, product.id, product.issuerId, product.rules.currency, "FEE");
      }

      for (const [key, balance] of plane.cashBalances) {
        if (balance === 0n) continue;
        const separator = key.lastIndexOf(":");
        const owner = key.slice(0, separator);
        const currency = key.slice(separator + 1);
        const product = [...plane.products.values()].find((item) => item.rules.currency === currency);
        if (!product) continue;
        const batchId = `opening:${product.id}:${owner}:${currency}`;
        const exists = await client.query("SELECT 1 FROM rwa.ledger_batches WHERE id=$1", [batchId]);
        if (exists.rowCount) continue;
        await this.store.appendLedgerBatch(client, {
          batchId,
          sourceType: "OPENING",
          entries: [
            { accountId: ledgerAccountId(product.id, owner, currency, "INVESTOR"), assetCode: currency, signedDelta: balance },
            { accountId: ledgerAccountId(product.id, "EXTERNAL_CASH", currency, "CASH_CLEARING"), assetCode: currency, signedDelta: -balance },
          ],
        });
      }
    });
  }

  async subscribe(request) {
    return this.#settle("SUBSCRIBE", request);
  }

  async transfer(request) {
    return this.#settle("TRANSFER", request);
  }

  async redeem(request) {
    return this.#settle("REDEEM", request);
  }

  async setProductStatus({ productId, status, actorRef, reason }) {
    fail(["ACTIVE", "PAUSED"].includes(status), "INVALID_PRODUCT_STATUS", "product status must be ACTIVE or PAUSED");
    fail(actorRef, "MISSING_ACTOR", "product status change requires an actor");
    return this.store.withSerializableTransaction(async (client) => {
      const current = await client.query("SELECT status FROM rwa.products WHERE id=$1 FOR UPDATE", [productId]);
      fail(current.rowCount === 1, "UNKNOWN_PRODUCT", "product not found");
      const expected = status === "PAUSED" ? "ACTIVE" : "PAUSED";
      fail(current.rows[0].status === expected, "INVALID_PRODUCT_STATE", `product must be ${expected} before transition`);
      await client.query(
        `UPDATE rwa.products SET status=$2,row_version=row_version+1,updated_at=clock_timestamp() WHERE id=$1`,
        [productId, status],
      );
      await this.store.recordAuditEvent(client, {
        tenantId: this.tenantId,
        eventType: `product.${status.toLowerCase()}`,
        aggregateType: "product",
        aggregateId: productId,
        metadata: { productId, status, actorRef, reason },
      });
      await this.store.enqueueOutbox(client, {
        tenantId: this.tenantId,
        topic: "rwa.product.status_changed",
        aggregateId: productId,
        payload: { productId, status, actorRef, reason },
      });
      return { productId, state: status };
    });
  }

  async restrictCredential({ credentialId, actorRef, reason }) {
    fail(actorRef, "MISSING_ACTOR", "credential restriction requires an actor");
    fail(reason, "MISSING_REASON", "credential restriction requires a reason");
    return this.store.withSerializableTransaction(async (client) => {
      const updated = await client.query(
        `UPDATE rwa.credentials
         SET status='RESTRICTED_EXIT',restriction_reason=$2
         WHERE id=$1 AND status='ACTIVE'
         RETURNING id,product_id,subject_ref,status,restriction_reason`,
        [credentialId, reason],
      );
      fail(updated.rowCount === 1, "INVALID_CREDENTIAL_STATE", "credential is not active");
      const row = updated.rows[0];
      await this.store.recordAuditEvent(client, {
        tenantId: this.tenantId,
        eventType: "credential.restricted_exit",
        aggregateType: "credential",
        aggregateId: row.id,
        metadata: { productId: row.product_id, subjectRefHash: sha256Canonical(row.subject_ref), actorRef, reason },
      });
      await this.store.enqueueOutbox(client, {
        tenantId: this.tenantId,
        topic: "rwa.credential.restricted",
        aggregateId: row.id,
        payload: { credentialId: row.id, productId: row.product_id, status: row.status },
      });
      return { credentialId: row.id, state: row.status, permittedAction: "REDEEM_ONLY" };
    });
  }

  async resetSandboxDemo({ productId, actorRef, navEvidence }) {
    fail(this.tenantId === TENANT, "SANDBOX_RESET_FORBIDDEN", "demo reset is limited to the sandbox tenant");
    fail(productId === "hk-liquidity-sandbox", "SANDBOX_RESET_FORBIDDEN", "demo reset is limited to the synthetic product");
    fail(actorRef, "MISSING_ACTOR", "demo reset requires an actor");
    fail(navEvidence?.id === "nav-demo-001" && navEvidence.productId === productId,
      "INVALID_DEMO_EVIDENCE", "fresh signed demo NAV evidence is required");

    return this.store.withSerializableTransaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtext('rwa:synthetic-demo-reset'))");
      const product = await client.query(
        "SELECT id,issuer_id FROM rwa.products WHERE id=$1 FOR UPDATE",
        [productId],
      );
      fail(product.rowCount === 1 && product.rows[0].issuer_id === "demo-issuer",
        "SANDBOX_RESET_FORBIDDEN", "synthetic demo product identity mismatch");

      // These tables are deliberately immutable in normal operation. The local Sandbox reset
      // owns the tables, takes ACCESS EXCLUSIVE locks and disables only USER triggers inside
      // this transaction. A rollback restores every trigger automatically. Production runtime
      // roles must not own the schema and therefore cannot execute this path.
      for (const table of SANDBOX_RESET_TRIGGER_TABLES) {
        await client.query(`ALTER TABLE rwa.${table} DISABLE TRIGGER USER`);
      }

      await client.query(
        `CREATE TEMP TABLE demo_reset_transactions ON COMMIT DROP AS
         SELECT id FROM rwa.transaction_intents WHERE product_id=$1 AND tenant_id=$2`,
        [productId, this.tenantId],
      );
      await client.query(
        `CREATE TEMP TABLE demo_reset_callbacks ON COMMIT DROP AS
         SELECT callback_id FROM rwa.callback_receipts WHERE product_id=$1 AND tenant_id=$2`,
        [productId, this.tenantId],
      );
      await client.query(
        `CREATE TEMP TABLE demo_reset_outbox ON COMMIT DROP AS
         SELECT id FROM rwa.outbox_events
         WHERE tenant_id=$2 AND (
           aggregate_id=$1 OR payload->>'productId'=$1 OR
           aggregate_id IN (SELECT id FROM demo_reset_transactions)
         )`,
        [productId, this.tenantId],
      );

      await client.query(`DELETE FROM rwa.dead_letter_replay_requests d USING demo_reset_outbox x WHERE d.event_id=x.id`);
      await client.query(`DELETE FROM rwa.inbox_consumptions i USING demo_reset_outbox x WHERE i.event_id=x.id`);
      await client.query(`DELETE FROM rwa.register_callback_events r USING demo_reset_outbox x WHERE r.event_id=x.id`);

      await client.query(
        `DELETE FROM rwa.external_incident_approvals a USING rwa.external_reconciliation_incidents i
         WHERE a.incident_id=i.id AND i.product_id=$1 AND i.tenant_id=$2`,
        [productId, this.tenantId],
      );
      await client.query(`DELETE FROM rwa.external_reconciliation_incidents WHERE product_id=$1 AND tenant_id=$2`, [productId, this.tenantId]);
      await client.query(`DELETE FROM rwa.external_callback_confirmations WHERE product_id=$1`, [productId]);
      await client.query(`DELETE FROM rwa.callback_applications a USING demo_reset_callbacks c WHERE a.callback_id=c.callback_id`);
      await client.query(`DELETE FROM rwa.callback_effects e USING demo_reset_callbacks c WHERE e.callback_id=c.callback_id`);
      await client.query(`DELETE FROM rwa.callback_evidence_records WHERE product_id=$1`, [productId]);
      await client.query(`DELETE FROM rwa.callback_receipts WHERE product_id=$1 AND tenant_id=$2`, [productId, this.tenantId]);
      await client.query(`DELETE FROM rwa.callback_stream_positions WHERE product_id=$1 AND tenant_id=$2`, [productId, this.tenantId]);

      await client.query(`DELETE FROM rwa.prover_jobs WHERE product_id=$1 AND tenant_id=$2`, [productId, this.tenantId]);
      await client.query(
        `DELETE FROM rwa.zk_root_publication_attestations a USING demo_reset_transactions t
         WHERE a.transaction_id=t.id`,
      );
      await client.query(
        `DELETE FROM rwa.zk_finalization_proposals p USING demo_reset_transactions t
         WHERE p.transaction_id=t.id`,
      );
      await client.query(`DELETE FROM rwa.zk_settlements WHERE product_id=$1 AND tenant_id=$2`, [productId, this.tenantId]);
      await client.query(
        `DELETE FROM rwa.zk_output_commitments o USING rwa.zk_proof_receipts p, demo_reset_transactions t
         WHERE o.proof_receipt_id=p.id AND p.transaction_id=t.id`,
      );
      await client.query(
        `DELETE FROM rwa.zk_spent_nullifiers n USING rwa.zk_proof_receipts p, demo_reset_transactions t
         WHERE n.proof_receipt_id=p.id AND p.transaction_id=t.id`,
      );
      await client.query(`DELETE FROM rwa.zk_transaction_authorizations a USING demo_reset_transactions t WHERE a.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.zk_execution_instructions i USING demo_reset_transactions t WHERE i.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.zk_proof_receipts p USING demo_reset_transactions t WHERE p.transaction_id=t.id`);

      await client.query(
        `DELETE FROM rwa.approval_records a USING rwa.exception_cases e, demo_reset_transactions t
         WHERE a.exception_id=e.id AND e.transaction_id=t.id`,
      );
      await client.query(`DELETE FROM rwa.exception_cases e USING demo_reset_transactions t WHERE e.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.transaction_receipts r USING demo_reset_transactions t WHERE r.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.transaction_economic_commitments e USING demo_reset_transactions t WHERE e.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.cash_confirmations c USING demo_reset_transactions t WHERE c.transaction_id=t.id`);

      await client.query(
        `DELETE FROM rwa.register_entries e USING rwa.register_batches b, demo_reset_transactions t
         WHERE e.batch_id=b.id AND b.transaction_id=t.id`,
      );
      await client.query(`DELETE FROM rwa.register_batches b USING demo_reset_transactions t WHERE b.transaction_id=t.id`);
      await client.query(
        `DELETE FROM rwa.ledger_entries e USING rwa.ledger_batches b, demo_reset_transactions t
         WHERE e.batch_id=b.id AND b.transaction_id=t.id`,
      );
      await client.query(`DELETE FROM rwa.ledger_batches b USING demo_reset_transactions t WHERE b.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.transaction_state_history h USING demo_reset_transactions t WHERE h.transaction_id=t.id`);
      await client.query(`DELETE FROM rwa.transaction_intents i USING demo_reset_transactions t WHERE i.id=t.id`);

      await client.query(`DELETE FROM rwa.outbox_events o USING demo_reset_outbox x WHERE o.id=x.id`);
      await client.query(
        `DELETE FROM rwa.audit_events
         WHERE tenant_id=$2 AND (
           aggregate_id=$1 OR metadata->>'productId'=$1 OR
           aggregate_id IN (SELECT id FROM demo_reset_transactions)
         )`,
        [productId, this.tenantId],
      );

      await client.query(
        `UPDATE rwa.products SET status='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp()
         WHERE id=$1`,
        [productId],
      );
      await client.query(
        `UPDATE rwa.credentials SET status='ACTIVE',restriction_reason=NULL
         WHERE product_id=$1 AND id IN ('credential-investor-a','credential-investor-b')`,
        [productId],
      );
      await client.query(
        `UPDATE rwa.evidence_envelopes SET
           data_type=$2,source_institution_id=$3,trust_tier=$4,schema_version=$5,
           effective_at=$6,expires_at=$7,payload=$8::jsonb,payload_hash=$9,signature=$10,status='ACTIVE'
         WHERE id=$1 AND product_id=$11`,
        [navEvidence.id, navEvidence.dataType, navEvidence.sourceInstitutionId, navEvidence.trustTier,
          navEvidence.schemaVersion, navEvidence.effectiveAt, navEvidence.expiresAt,
          JSON.stringify(navEvidence.payload), sha256Canonical(navEvidence.payload), navEvidence.signature, productId],
      );

      await this.store.recordAuditEvent(client, {
        tenantId: this.tenantId,
        eventType: "sandbox.demo_reset",
        aggregateType: "product",
        aggregateId: productId,
        metadata: { productId, actorRef, syntheticOnly: true },
      });

      for (const table of SANDBOX_RESET_TRIGGER_TABLES) {
        await client.query(`ALTER TABLE rwa.${table} ENABLE TRIGGER USER`);
      }

      return {
        state: "DEMO_READY",
        productId,
        navEvidenceId: navEvidence.id,
        navExpiresAt: navEvidence.expiresAt,
        syntheticOnly: true,
      };
    });
  }

  async proposeExceptionResolution({ caseId, makerId, decision, replacementTransactionId = null }) {
    return this.store.withSerializableTransaction(async (client) => {
      const proposed = await this.store.proposeExceptionResolution(client, {
        exceptionId: caseId,
        makerRef: makerId,
        decision,
        replacementTransactionId,
      });
      await this.store.transitionTransaction(client, {
        transactionId: proposed.exception.transaction_id,
        toState: "PENDING_APPROVAL",
        actorRef: makerId,
      });
      await this.store.recordAuditEvent(client, {
        tenantId: this.tenantId,
        eventType: "exception.resolution_proposed",
        aggregateType: "transaction",
        aggregateId: proposed.exception.transaction_id,
        metadata: {
          productId: proposed.exception.product_id,
          exceptionCaseId: caseId,
          approvalRound: proposed.approvalRound,
          decision,
          makerId,
        },
      });
      await this.store.enqueueOutbox(client, {
        tenantId: this.tenantId,
        topic: "rwa.exception.resolution_proposed",
        aggregateId: proposed.exception.transaction_id,
        payload: { exceptionCaseId: caseId, approvalRound: proposed.approvalRound, decision },
      });
      return { caseId, state: "PENDING_APPROVAL", decision, replacementTransactionId, makerId };
    });
  }

  async approveExceptionResolution({ caseId, checkerId, decision = "APPROVE" }) {
    return this.store.withSerializableTransaction(async (client) => {
      const approval = await this.store.approveExceptionResolution(client, {
        exceptionId: caseId,
        checkerRef: checkerId,
        decision,
      });
      const originalId = approval.exception.transaction_id;
      if (decision === "REJECT") {
        await this.store.transitionTransaction(client, { transactionId: originalId, toState: "REQUIRES_REVIEW", actorRef: checkerId });
        await this.store.returnExceptionForReview(client, { exceptionId: caseId });
        await this.#recordExceptionDecision(client, approval, caseId, checkerId, "OPEN", "CHECKER_REJECTED");
        return { caseId, state: "OPEN", checkerId, decision };
      }
      if (approval.proposalDecision === "CANCEL") {
        await this.store.transitionTransaction(client, { transactionId: originalId, toState: "CANCELLED", actorRef: checkerId });
        await this.store.resolveExceptionCase(client, { exceptionId: caseId, status: "RESOLVED_CANCELLED" });
        await this.#recordExceptionDecision(client, approval, caseId, checkerId, "RESOLVED_CANCELLED", null);
        return { caseId, state: "RESOLVED_CANCELLED", makerId: approval.makerRef, checkerId };
      }

      const original = await client.query(
        `SELECT id,tenant_id,product_id,transaction_type,private_payload_ciphertext
         FROM rwa.transaction_intents WHERE id=$1 FOR UPDATE`,
        [originalId],
      );
      fail(original.rowCount === 1, "UNKNOWN_TRANSACTION", "original transaction is missing");
      const row = original.rows[0];
      const originalRequest = await this.payloadCipher.decrypt(row.private_payload_ciphertext, {
        tenantId: row.tenant_id,
        transactionId: row.id,
        productId: row.product_id,
        transactionType: row.transaction_type,
      });
      const replacementRequest = {
        ...originalRequest,
        id: approval.replacementTransactionId,
        idempotencyKey: `exception-retry:${caseId}:${approval.replacementTransactionId}`,
      };
      await client.query("SAVEPOINT exception_retry_attempt");
      let replacement;
      try {
        replacement = await this.#settleInTransaction(client, row.transaction_type, replacementRequest);
        await client.query("RELEASE SAVEPOINT exception_retry_attempt");
      } catch (error) {
        await client.query("ROLLBACK TO SAVEPOINT exception_retry_attempt");
        await this.store.transitionTransaction(client, {
          transactionId: originalId,
          toState: "REQUIRES_REVIEW",
          reasonCode: error.code ?? "RETRY_BLOCKED",
          actorRef: checkerId,
        });
        await this.store.returnExceptionForReview(client, { exceptionId: caseId });
        await this.#recordExceptionDecision(client, approval, caseId, checkerId, "OPEN", error.code ?? "RETRY_BLOCKED");
        return { caseId, state: "OPEN", retryBlocked: true, reasonCode: error.code ?? "RETRY_BLOCKED" };
      }
      await this.store.transitionTransaction(client, { transactionId: originalId, toState: "REPLACED", actorRef: checkerId });
      await this.store.resolveExceptionCase(client, {
        exceptionId: caseId,
        status: "RESOLVED_RETRIED",
        replacementTransactionId: approval.replacementTransactionId,
      });
      await this.#recordExceptionDecision(client, approval, caseId, checkerId, "RESOLVED_RETRIED", null);
      return {
        caseId,
        state: "RESOLVED_RETRIED",
        makerId: approval.makerRef,
        checkerId,
        replacement,
      };
    });
  }

  async #recordExceptionDecision(client, approval, caseId, checkerId, state, reasonCode) {
    const metadata = {
      productId: approval.exception.product_id,
      exceptionCaseId: caseId,
      approvalRound: approval.exception.approval_round,
      checkerId,
      state,
      reasonCode,
    };
    await this.store.recordAuditEvent(client, {
      tenantId: this.tenantId,
      eventType: state.startsWith("RESOLVED_") ? "exception.resolved" : "exception.retry_blocked",
      aggregateType: "transaction",
      aggregateId: approval.exception.transaction_id,
      metadata,
    });
    await this.store.enqueueOutbox(client, {
      tenantId: this.tenantId,
      topic: "rwa.exception.decision_recorded",
      aggregateId: approval.exception.transaction_id,
      payload: metadata,
    });
  }

  async simulateRegisterFailure(request) {
    return this.store.withSerializableTransaction((client) => (
      this.#settleInTransaction(client, "TRANSFER", request, { registerFailure: true })
    ));
  }

  async #settle(type, request) {
    return this.store.withSerializableTransaction((client) => this.#settleInTransaction(client, type, request));
  }

  async #settleInTransaction(client, type, request, { registerFailure = false } = {}) {
      // Replays are answered before any balance, NAV or status check, so a
      // retried success returns its receipt instead of a spurious business error.
      const replay = await client.query(
        `SELECT t.id,t.request_hash,r.receipt FROM rwa.transaction_intents t
         LEFT JOIN rwa.transaction_receipts r ON r.transaction_id=t.id
         WHERE t.tenant_id=$1 AND t.idempotency_key=$2 FOR SHARE OF t`,
        [this.tenantId, request.idempotencyKey],
      );
      if (replay.rowCount === 1) {
        fail(replay.rows[0].request_hash === sha256Canonical(request), "IDEMPOTENCY_CONFLICT", "idempotency key reused for a different request");
        fail(replay.rows[0].receipt, "IDEMPOTENCY_IN_FLIGHT", "transaction receipt is not available");
        return replay.rows[0].receipt;
      }
      const productResult = await client.query("SELECT * FROM rwa.products WHERE id=$1 AND status='ACTIVE' FOR SHARE", [request.productId]);
      fail(productResult.rowCount === 1, "PRODUCT_NOT_ACTIVE", "product is not active");
      const product = productResult.rows[0];
      const rules = product.rules;
      const navResult = await client.query(
        `SELECT * FROM rwa.evidence_envelopes
         WHERE product_id=$1 AND data_type='nav' AND status='ACTIVE'
           AND effective_at <= $2 AND expires_at > $2
         ORDER BY effective_at DESC LIMIT 1 FOR SHARE`,
        [product.id, this.now().toISOString()],
      );
      fail(navResult.rowCount === 1, "MISSING_EVIDENCE", "current NAV evidence is missing");
      const nav = navResult.rows[0];
      fail(nav.payload.currency === product.currency, "EVIDENCE_CURRENCY", "NAV currency does not match product");
      const unitAsset = `UNIT:${product.id}`;
      const units = positive(request.units, "units");
      const navPrice = BigInt(nav.payload.navPerUnit);
      let cashAmount;
      let settlementMode = "STANDARD";
      let ledgerEntries;
      let registerEntries;

      if (type === "SUBSCRIBE") {
        await this.#assertCredential(client, product, request.investorId, request.credentialId, units, false);
        cashAmount = positive(request.cashAmount, "cashAmount");
        fail(cashAmount === units * navPrice, "PRICE_MISMATCH", "subscription amount does not match current NAV");
        const investorCash = ledgerAccountId(product.id, request.investorId, rules.currency, "INVESTOR");
        fail(await this.store.accountBalance(client, { accountId: investorCash }) >= cashAmount, "INSUFFICIENT_CASH", "insufficient cash");
        ledgerEntries = [
          { accountId: investorCash, assetCode: rules.currency, signedDelta: -cashAmount },
          { accountId: ledgerAccountId(product.id, product.issuer_id, rules.currency, "ISSUER"), assetCode: rules.currency, signedDelta: cashAmount },
          { accountId: ledgerAccountId(product.id, "TREASURY", unitAsset, "TREASURY"), assetCode: unitAsset, signedDelta: -units },
          { accountId: ledgerAccountId(product.id, request.investorId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: units },
        ];
        registerEntries = [
          { accountId: registerAccountId(product.id, "TREASURY", unitAsset, "TREASURY"), assetCode: unitAsset, signedDelta: -units },
          { accountId: registerAccountId(product.id, request.investorId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: units },
        ];
      } else if (type === "TRANSFER") {
        fail(new Date(request.expiresAt) > this.now(), "TRANSACTION_EXPIRED", "transaction intent expired");
        fail(request.sellerId !== request.buyerId, "SELF_TRANSFER", "seller and buyer must differ");
        await this.#assertCredential(client, product, request.sellerId, request.sellerCredentialId, 0n, false);
        await this.#assertCredential(client, product, request.buyerId, request.buyerCredentialId, units, false);
        const price = positive(request.pricePerUnit, "pricePerUnit");
        const fee = BigInt(request.fee ?? "0");
        fail(fee >= 0n, "INVALID_AMOUNT", "fee must be non-negative");
        const deviation = price > navPrice ? price - navPrice : navPrice - price;
        fail(deviation * 10_000n <= navPrice * BigInt(rules.maxPriceDeviationBps), "PRICE_DEVIATION", "price exceeds NAV band");
        cashAmount = units * price;
        const sellerUnit = ledgerAccountId(product.id, request.sellerId, unitAsset, "INVESTOR");
        const buyerCash = ledgerAccountId(product.id, request.buyerId, rules.currency, "INVESTOR");
        fail(await this.store.accountBalance(client, { accountId: sellerUnit }) >= units, "INSUFFICIENT_ASSET", "seller units insufficient");
        fail(await this.store.accountBalance(client, { accountId: buyerCash }) >= cashAmount + fee, "INSUFFICIENT_CASH", "buyer cash insufficient");
        ledgerEntries = [
          { accountId: buyerCash, assetCode: rules.currency, signedDelta: -(cashAmount + fee) },
          { accountId: ledgerAccountId(product.id, request.sellerId, rules.currency, "INVESTOR"), assetCode: rules.currency, signedDelta: cashAmount },
          ...(fee === 0n ? [] : [{ accountId: ledgerAccountId(product.id, product.issuer_id, rules.currency, "FEE"), assetCode: rules.currency, signedDelta: fee }]),
          { accountId: sellerUnit, assetCode: unitAsset, signedDelta: -units },
          { accountId: ledgerAccountId(product.id, request.buyerId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: units },
        ];
        registerEntries = [
          { accountId: registerAccountId(product.id, request.sellerId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: -units },
          { accountId: registerAccountId(product.id, request.buyerId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: units },
        ];
      } else {
        const credentialStatus = await this.#assertCredential(client, product, request.investorId, request.credentialId, 0n, true);
        settlementMode = credentialStatus === "RESTRICTED_EXIT" ? "RESTRICTED_EXIT" : "STANDARD";
        cashAmount = units * navPrice;
        const investorUnit = ledgerAccountId(product.id, request.investorId, unitAsset, "INVESTOR");
        const issuerCash = ledgerAccountId(product.id, product.issuer_id, rules.currency, "ISSUER");
        fail(await this.store.accountBalance(client, { accountId: investorUnit }) >= units, "INSUFFICIENT_ASSET", "investor units insufficient");
        fail(await this.store.accountBalance(client, { accountId: issuerCash }) >= cashAmount, "INSUFFICIENT_REDEMPTION_CASH", "issuer cash insufficient");
        ledgerEntries = [
          { accountId: issuerCash, assetCode: rules.currency, signedDelta: -cashAmount },
          { accountId: ledgerAccountId(product.id, request.investorId, rules.currency, "INVESTOR"), assetCode: rules.currency, signedDelta: cashAmount },
          { accountId: investorUnit, assetCode: unitAsset, signedDelta: -units },
          { accountId: ledgerAccountId(product.id, "TREASURY", unitAsset, "TREASURY"), assetCode: unitAsset, signedDelta: units },
        ];
        registerEntries = [
          { accountId: registerAccountId(product.id, request.investorId, unitAsset, "INVESTOR"), assetCode: unitAsset, signedDelta: -units },
          { accountId: registerAccountId(product.id, "TREASURY", unitAsset, "TREASURY"), assetCode: unitAsset, signedDelta: units },
        ];
      }

      const policySnapshotHash = sha256Canonical({ ruleVersion: product.rule_version, rules, navEvidenceId: nav.id });
      const distributor = await client.query(
        `SELECT institution_id FROM rwa.product_role_assignments
         WHERE product_id=$1 AND role='distributor' AND ended_at IS NULL`,
        [product.id],
      );
      const created = await this.store.createTransactionIntent(client, {
        id: request.id,
        tenantId: this.tenantId,
        productId: product.id,
        idempotencyKey: request.idempotencyKey,
        request,
        transactionType: type,
        ruleVersion: product.rule_version,
        navEvidenceId: nav.id,
        policySnapshotHash,
        privatePayloadCiphertext: await this.payloadCipher.encrypt(request, {
          tenantId: this.tenantId,
          transactionId: request.id,
          productId: product.id,
          transactionType: type,
        }),
        originatingInstitutionId: distributor.rows[0]?.institution_id ?? null,
        partyIndex: await partyIndexFor(this.economicCommitter, {
          tenantId: this.tenantId, productId: product.id, request,
        }),
        actorRef: "sandbox-workflow",
      });
      if (!created.created) {
        const existing = await client.query("SELECT receipt FROM rwa.transaction_receipts WHERE transaction_id=$1", [created.transaction.id]);
        fail(existing.rowCount === 1, "IDEMPOTENCY_IN_FLIGHT", "transaction receipt is not available");
        return existing.rows[0].receipt;
      }
      fail(this.economicCommitter, "ECONOMIC_COMMITTER_REQUIRED", "economic commitment service is required");
      const feeAmount = type === "TRANSFER" ? BigInt(request.fee ?? "0") : 0n;
      const commitmentContext = { tenantId: this.tenantId, transactionId: request.id, productId: product.id };
      await client.query(
        `INSERT INTO rwa.transaction_economic_commitments
         (transaction_id,commitment_version,key_id,asset_code,currency,units_commitment,cash_amount_commitment,fee_amount_commitment)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [request.id, this.economicCommitter.version, this.economicCommitter.keyId, unitAsset, product.currency,
          await this.economicCommitter.commit({ ...commitmentContext, field: "units", value: units }),
          await this.economicCommitter.commit({ ...commitmentContext, field: "cashAmountMinor", value: cashAmount }),
          await this.economicCommitter.commit({ ...commitmentContext, field: "feeAmountMinor", value: feeAmount })],
      );

      if (registerFailure) {
        for (const state of ["POLICY_CHECKED", "CASH_RESERVED"]) {
          await this.store.transitionTransaction(client, { transactionId: request.id, toState: state, actorRef: "sandbox-workflow" });
        }
        const cashProvider = await client.query(
          `SELECT institution_id FROM rwa.product_role_assignments
           WHERE product_id=$1 AND role='cash_provider' AND ended_at IS NULL`,
          [product.id],
        );
        fail(cashProvider.rowCount === 1, "MISSING_ROLE", "cash provider assignment is missing");
        await client.query(
          `INSERT INTO rwa.cash_confirmations(transaction_id,source_institution_id,state,external_reference,signed_receipt)
           VALUES ($1,$2,'RELEASED',$3,$4::jsonb)`,
          [request.id, cashProvider.rows[0].institution_id, `sandbox-released:${request.id}`,
            JSON.stringify({ mode: "SANDBOX_REGISTER_TIMEOUT" })],
        );
        await this.store.transitionTransaction(client, {
          transactionId: request.id,
          toState: "REQUIRES_REVIEW",
          reasonCode: "REGISTER_TIMEOUT",
          actorRef: "sandbox-workflow",
        });
        const exceptionCaseId = `case-${request.id}`;
        await client.query(
          `INSERT INTO rwa.exception_cases
           (id,transaction_id,product_id,status,failure_stage,reason_code)
           VALUES ($1,$2,$3,'OPEN','REGISTER_PENDING','REGISTER_TIMEOUT')`,
          [exceptionCaseId, request.id, product.id],
        );
        const receipt = {
          transactionId: request.id,
          productId: product.id,
          type,
          state: "REQUIRES_REVIEW",
          settledAt: null,
          navEvidenceId: nav.id,
          ruleVersion: product.rule_version,
          settlementMode: "EXCEPTION_REVIEW",
          lifecycle: ["REQUESTED", "POLICY_CHECKED", "CASH_RESERVED", "REQUIRES_REVIEW"],
          proofSystem: "SANDBOX_NO_ZK_PROOF",
          exceptionCaseId,
          reasonCode: "REGISTER_TIMEOUT",
        };
        const receiptHash = await this.store.storeReceipt(client, { transactionId: request.id, receipt });
        await this.store.recordAuditEvent(client, {
          tenantId: this.tenantId,
          eventType: "exception.opened",
          aggregateType: "transaction",
          aggregateId: request.id,
          metadata: { productId: product.id, state: "REQUIRES_REVIEW", reasonCode: "REGISTER_TIMEOUT", receiptHash },
        });
        await this.store.enqueueOutbox(client, {
          tenantId: this.tenantId,
          topic: "rwa.exception.opened",
          aggregateId: request.id,
          payload: { transactionId: request.id, productId: product.id, exceptionCaseId, reasonCode: "REGISTER_TIMEOUT" },
        });
        return receipt;
      }

      for (const state of ["POLICY_CHECKED", "CASH_RESERVED", "REGISTER_PENDING"]) {
        await this.store.transitionTransaction(client, { transactionId: request.id, toState: state, actorRef: "sandbox-workflow" });
      }
      await this.store.appendLedgerBatch(client, { batchId: `ledger:${request.id}`, transactionId: request.id, entries: ledgerEntries });
      await this.store.appendRegisterBatch(client, {
        batchId: `register:${request.id}`, transactionId: request.id, assetCode: unitAsset, entries: registerEntries,
      });
      const cashProvider = await client.query(
        `SELECT institution_id FROM rwa.product_role_assignments
         WHERE product_id=$1 AND role='cash_provider' AND ended_at IS NULL`,
        [product.id],
      );
      fail(cashProvider.rowCount === 1, "MISSING_ROLE", "cash provider assignment is missing");
      await client.query(
        `INSERT INTO rwa.cash_confirmations(transaction_id,source_institution_id,state,external_reference,signed_receipt)
         VALUES ($1,$2,'CONFIRMED',$3,$4::jsonb)`,
        [request.id, cashProvider.rows[0].institution_id, `sandbox:${request.id}`, JSON.stringify({ mode: "SANDBOX_JOURNAL" })],
      );
      await this.store.transitionTransaction(client, { transactionId: request.id, toState: "SETTLED", actorRef: "sandbox-workflow" });

      const receipt = {
        transactionId: request.id,
        productId: product.id,
        type,
        state: "SETTLED",
        settledAt: this.now().toISOString(),
        navEvidenceId: nav.id,
        ruleVersion: product.rule_version,
        settlementMode,
        lifecycle: ["REQUESTED", "POLICY_CHECKED", "CASH_RESERVED", "REGISTER_PENDING", "SETTLED"],
        proofSystem: "SANDBOX_NO_ZK_PROOF",
      };
      const receiptHash = await this.store.storeReceipt(client, { transactionId: request.id, receipt });
      await this.store.recordAuditEvent(client, {
        tenantId: this.tenantId,
        eventType: `${type.toLowerCase()}.settled`,
        aggregateType: "transaction",
        aggregateId: request.id,
        metadata: { productId: product.id, state: "SETTLED", receiptHash },
      });
      await this.store.enqueueOutbox(client, {
        tenantId: this.tenantId,
        topic: "rwa.transaction.settled",
        aggregateId: request.id,
        payload: { transactionId: request.id, productId: product.id, type, state: "SETTLED", receiptHash },
      });
      return receipt;
  }

  async #assertCredential(client, product, subjectRef, credentialId, additionalUnits, allowRestrictedExit) {
    const result = await client.query("SELECT * FROM rwa.credentials WHERE id=$1 AND product_id=$2 FOR SHARE", [credentialId, product.id]);
    fail(result.rowCount === 1, "UNKNOWN_CREDENTIAL", "credential not found");
    const credential = result.rows[0];
    fail(credential.subject_ref === subjectRef, "CREDENTIAL_SUBJECT", "credential subject mismatch");
    const now = this.now();
    fail(new Date(credential.valid_from) <= now && new Date(credential.valid_until) > now, "CREDENTIAL_TIME", "credential not active");
    fail(credential.status === "ACTIVE" || (allowRestrictedExit && credential.status === "RESTRICTED_EXIT"), "CREDENTIAL_REVOKED", "credential is restricted");
    fail(product.rules.allowedInvestorClasses.includes(credential.investor_class), "INVESTOR_CLASS", "investor class not allowed");
    fail(product.rules.allowedJurisdictions.includes(credential.jurisdiction), "INVESTOR_JURISDICTION", "jurisdiction not allowed");
    if (additionalUnits > 0n) {
      const assetCode = `UNIT:${product.id}`;
      const accountId = registerAccountId(product.id, subjectRef, assetCode, "INVESTOR");
      const current = await this.store.accountBalance(client, { table: "register", accountId });
      fail(current + additionalUnits <= BigInt(credential.max_units), "HOLDING_LIMIT", "holding limit exceeded");
    }
    return credential.status;
  }

  async #ensureLedgerAccount(client, productId, ownerRef, assetCode, accountType) {
    await client.query(
      `INSERT INTO rwa.ledger_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
       VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
      [ledgerAccountId(productId, ownerRef, assetCode, accountType), this.tenantId, productId, ownerRef, assetCode, accountType],
    );
  }

  async #ensureRegisterAccount(client, productId, ownerRef, assetCode, accountType) {
    await client.query(
      `INSERT INTO rwa.register_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
       VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
      [registerAccountId(productId, ownerRef, assetCode, accountType), this.tenantId, productId, ownerRef, assetCode, accountType],
    );
  }
}
