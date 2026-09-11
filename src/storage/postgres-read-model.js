function denied(message) {
  const error = new Error(message);
  error.code = "DISCLOSURE_DENIED";
  throw error;
}

const METADATA_ROLES = new Set(["issuer", "operations", "supervisor"]);
const VIEW_ROLES = new Set(["issuer", "distributor", "investor", "broker", "operations", "supervisor"]);

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function credentialStatus(row, now) {
  if (new Date(row.valid_from) > now) return "PENDING";
  if (new Date(row.valid_until) <= now) return "EXPIRED";
  return row.status;
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const IDENTIFIER_KEYS = new Set([
  "actorRef", "makerRef", "checkerRef", "subjectRef", "investorId", "buyerId", "sellerId",
  "principalId", "proposedBy", "finalizedBy", "maker", "checker",
]);

function redactIdentifiers(value) {
  if (Array.isArray(value)) return value.map(redactIdentifiers);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key, IDENTIFIER_KEYS.has(key) && item !== null ? "[REDACTED]" : redactIdentifiers(item),
  ]));
}

export class PostgresReadModel {
  constructor(store, { payloadCipher, tenantId = "sandbox-hk", now = () => new Date() }) {
    this.store = store;
    this.payloadCipher = payloadCipher;
    this.tenantId = tenantId;
    this.now = now;
  }

  async transactionForRole({ transactionId, role, actorRef = null }) {
    return this.#transactionForRole(this.store.pool, { transactionId, role, actorRef });
  }

  async transactionEvidencePackage({ transactionId, role, institutionId = null }) {
    if (!new Set(["issuer", "broker", "operations", "supervisor"]).has(role)) {
      denied("role cannot access transaction evidence packages");
    }
    const discloseOperationalIdentifiers = new Set(["broker", "operations"]).has(role);
    const { createHash } = await import("node:crypto");
    const client = await this.store.pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const transaction = await client.query(
        `SELECT t.id,t.product_id,t.transaction_type,t.current_state,t.settlement_rail,t.request_hash,t.originating_institution_id,
                t.rule_version,t.nav_evidence_id,t.policy_snapshot_hash,t.created_at,t.updated_at,
                r.receipt_hash,z.finality_domain,z.finality_status,z.legal_register_applied,z.settled_at
         FROM rwa.transaction_intents t
         LEFT JOIN rwa.transaction_receipts r ON r.transaction_id=t.id
         LEFT JOIN rwa.zk_settlements z ON z.transaction_id=t.id
         WHERE t.id=$1 AND t.tenant_id=$2`,
        [transactionId, this.tenantId],
      );
      if (transaction.rowCount !== 1
          || (role === "broker" && (!institutionId || transaction.rows[0].originating_institution_id !== institutionId))) {
        const error = new Error("transaction not found");
        error.code = "UNKNOWN_TRANSACTION";
        throw error;
      }
      // One transaction owns one connection: await each query on that client.
      const [history, audit, external, commitment, proof] = [
        await client.query(
          `SELECT from_state,to_state,reason_code,actor_ref,occurred_at
           FROM rwa.transaction_state_history WHERE transaction_id=$1 ORDER BY sequence_id`,
          [transactionId],
        ),
        await client.query(
          `SELECT sequence_id,event_type,metadata,previous_hash,event_hash,occurred_at
           FROM rwa.audit_events WHERE tenant_id=$1 AND aggregate_type='transaction' AND aggregate_id=$2
           ORDER BY sequence_id`,
          [this.tenantId, transactionId],
        ),
        await client.query(
          `SELECT register_outcome,cash_outcome,external_status
           FROM rwa.transaction_external_reconciliation WHERE transaction_id=$1`,
          [transactionId],
        ),
        await client.query(
          `SELECT commitment_version,key_id,asset_code,currency,units_commitment,
                  cash_amount_commitment,fee_amount_commitment,created_at
           FROM rwa.transaction_economic_commitments WHERE transaction_id=$1`,
          [transactionId],
        ),
        await client.query(
          `SELECT r.id,r.circuit_id,r.circuit_version,r.context_id::text,r.merkle_root::text,
                  r.verification_key_hash,r.proof_hash,r.public_signals_hash,r.status,r.verified_at,
                  (SELECT count(*)::int FROM rwa.zk_spent_nullifiers n WHERE n.proof_receipt_id=r.id) AS nullifier_count,
                  (SELECT count(*)::int FROM rwa.zk_output_commitments o WHERE o.proof_receipt_id=r.id) AS output_count
           FROM rwa.zk_proof_receipts r WHERE r.transaction_id=$1`,
          [transactionId],
        ),
      ];
      const row = transaction.rows[0];
      const evidencePackage = {
        schema: "rwa.transaction-evidence.v1",
        transaction: {
          id: row.id,
          productId: row.product_id,
          type: row.transaction_type,
          state: row.current_state,
          settlementRail: row.settlement_rail,
          requestHash: row.request_hash,
          ruleVersion: row.rule_version,
          navEvidenceId: row.nav_evidence_id,
          policySnapshotHash: row.policy_snapshot_hash,
          receiptHash: row.receipt_hash,
          finalityDomain: row.finality_domain,
          finalityStatus: row.finality_status,
          legalRegisterApplied: row.legal_register_applied,
          createdAt: iso(row.created_at),
          updatedAt: iso(row.updated_at),
          settledAt: iso(row.settled_at),
        },
        stateHistory: history.rows.map((item) => ({
          from: item.from_state,
          to: item.to_state,
          reasonCode: item.reason_code,
          actorRef: discloseOperationalIdentifiers ? item.actor_ref : "[REDACTED]",
          at: iso(item.occurred_at),
        })),
        economicCommitment: commitment.rows[0] ?? null,
        externalReconciliation: external.rows,
        zkProofReceipt: proof.rows[0] ?? null,
        auditChain: audit.rows.map((item) => ({
          sequence: Number(item.sequence_id),
          type: item.event_type,
          metadata: discloseOperationalIdentifiers ? item.metadata : redactIdentifiers(item.metadata),
          previousHash: item.previous_hash,
          eventHash: item.event_hash,
          at: iso(item.occurred_at),
        })),
      };
      const packageHash = createHash("sha256").update(canonicalize(evidencePackage)).digest("hex");
      await client.query("COMMIT");
      return {
        ...evidencePackage,
        generatedAt: this.now().toISOString(),
        packageHash,
        disclosure: discloseOperationalIdentifiers
          ? "NO_PRIVATE_ECONOMICS_OPERATIONAL_IDENTIFIERS"
          : "NO_PRIVATE_ECONOMICS_IDENTIFIERS_REDACTED",
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async viewForRole({ productId, role, actorRef = null, institutionId = null }) {
    if (!VIEW_ROLES.has(role)) denied("unknown product view role");
    if (role === "investor" && !actorRef) denied("investor identity is required");

    const client = await this.store.pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const productResult = await client.query(
        `SELECT p.*
         FROM rwa.products p
         WHERE p.id=$1 AND EXISTS (
           SELECT 1 FROM rwa.ledger_accounts a
           WHERE a.product_id=p.id AND a.tenant_id=$2
         )`,
        [productId, this.tenantId],
      );
      if (productResult.rowCount !== 1) {
        const error = new Error("product not found for tenant");
        error.code = "UNKNOWN_PRODUCT";
        throw error;
      }
      const productRow = productResult.rows[0];
      const base = {
        role,
        storageMode: "POSTGRESQL",
        generatedAt: this.now().toISOString(),
        product: {
          id: productRow.id,
          name: productRow.name,
          jurisdiction: productRow.jurisdiction,
          status: productRow.status,
          ruleVersion: productRow.rule_version,
          rules: productRow.rules,
        },
      };

      const reconciliation = await this.#reconciliation(client, productRow);
      const evidence = await this.#evidence(client, productId);
      const transactionSummary = await this.#transactionSummary(client, productId);

      let view;
      if (role === "issuer") {
        const assignments = await client.query(
          `SELECT role,institution_id FROM rwa.product_role_assignments
           WHERE product_id=$1 AND ended_at IS NULL ORDER BY role`,
          [productId],
        );
        view = {
          ...base,
          roleAssignments: Object.fromEntries(assignments.rows.map((row) => [row.role, row.institution_id])),
          evidence,
          reconciliation,
          transactionSummary,
        };
      } else if (role === "distributor") {
        const assigned = await client.query(
          `SELECT 1 FROM rwa.product_role_assignments
           WHERE product_id=$1 AND institution_id=$2 AND role IN ('distributor','credential_issuer') AND ended_at IS NULL`,
          [productId, institutionId],
        );
        if (assigned.rowCount === 0) denied("distributor institution is not assigned to this product");
        const credentials = await client.query(
          `SELECT id,subject_ref,investor_class,jurisdiction,max_units::text,valid_from,valid_until,status,restriction_reason
           FROM rwa.credentials WHERE product_id=$1 ORDER BY id`,
          [productId],
        );
        view = {
          ...base,
          credentials: credentials.rows.map((row) => ({
            id: row.id,
            subjectId: row.subject_ref,
            investorClass: row.investor_class,
            jurisdiction: row.jurisdiction,
            maxUnits: row.max_units,
            validUntil: iso(row.valid_until),
            status: credentialStatus(row, this.now()),
            restriction: row.restriction_reason
              ? { status: row.status, reason: row.restriction_reason }
              : null,
          })),
        };
      } else if (role === "investor") {
        const [position, cash, credential, transactionIds] = [
          await this.#accountBalance(client, "ledger", productId, actorRef, `UNIT:${productId}`),
          await this.#accountBalance(client, "ledger", productId, actorRef, productRow.currency),
          await client.query(
            `SELECT id,investor_class,jurisdiction,max_units::text,valid_from,valid_until,status,restriction_reason
             FROM rwa.credentials WHERE product_id=$1 AND subject_ref=$2
             ORDER BY created_at DESC LIMIT 1`,
            [productId, actorRef],
          ),
          await client.query(
            `SELECT id FROM rwa.transaction_intents
             WHERE tenant_id=$1 AND product_id=$2 ORDER BY created_at,id`,
            [this.tenantId, productId],
          ),
        ];
        const ownTransactions = [];
        for (const row of transactionIds.rows) {
          try {
            const disclosed = await this.#transactionForRole(client, {
              transactionId: row.id, role: "investor", actorRef,
            });
            const payload = disclosed.privatePayload;
            ownTransactions.push({
              id: disclosed.transactionId,
              type: disclosed.type,
              state: disclosed.state,
              units: payload.units,
              cashAmount: payload.cashAmount ?? (payload.pricePerUnit
                ? (BigInt(payload.units) * BigInt(payload.pricePerUnit)).toString()
                : null),
              fee: payload.fee ?? "0",
              settlementMode: disclosed.receipt?.settlementMode ?? null,
              settledAt: disclosed.receipt?.settledAt ?? null,
            });
          } catch (error) {
            if (error.code !== "DISCLOSURE_DENIED") throw error;
          }
        }
        const credentialRow = credential.rows[0];
        view = {
          ...base,
          actorId: actorRef,
          positionUnits: position,
          cashBalance: cash,
          credential: credentialRow ? {
            id: credentialRow.id,
            investorClass: credentialRow.investor_class,
            jurisdiction: credentialRow.jurisdiction,
            maxUnits: credentialRow.max_units,
            validUntil: iso(credentialRow.valid_until),
            status: credentialStatus(credentialRow, this.now()),
            restriction: credentialRow.restriction_reason
              ? { status: credentialRow.status, reason: credentialRow.restriction_reason }
              : null,
          } : null,
          ownTransactions,
        };
      } else if (role === "broker") {
        const transactionIds = await client.query(
          `SELECT id FROM rwa.transaction_intents
           WHERE tenant_id=$1 AND product_id=$2 AND originating_institution_id=$3 ORDER BY created_at,id`,
          [this.tenantId, productId, institutionId],
        );
        const transactions = [];
        for (const row of transactionIds.rows) {
          const disclosed = await this.#transactionForRole(client, {
            transactionId: row.id, role: "broker", actorRef,
          });
          const payload = disclosed.privatePayload;
          transactions.push({
            id: disclosed.transactionId,
            type: disclosed.type,
            sellerId: payload.sellerId ?? null,
            buyerId: payload.buyerId ?? payload.investorId ?? null,
            units: payload.units,
            pricePerUnit: payload.pricePerUnit ?? null,
            fee: payload.fee ?? "0",
            state: disclosed.state,
            settlementRail: disclosed.settlementRail,
            finalityDomain: disclosed.finalityDomain,
            finalityStatus: disclosed.finalityStatus,
            legalRegisterApplied: disclosed.legalRegisterApplied,
            settledAt: disclosed.receipt?.settledAt ?? null,
            navEvidenceId: disclosed.navEvidenceId,
            ruleVersion: disclosed.ruleVersion,
            policySnapshotHash: disclosed.policySnapshotHash,
            settlementMode: disclosed.receipt?.settlementMode ?? null,
            lifecycle: disclosed.receipt?.lifecycle?.map((state) => ({ state, at: null })) ?? [],
          });
        }
        view = { ...base, transactions };
      } else if (role === "operations") {
        view = {
          ...base,
          evidence,
          reconciliation,
          transactionSummary,
          exceptions: await this.#exceptions(client, productId),
        };
      } else {
        const audit = await client.query(
          `SELECT sequence_id,event_type,aggregate_id,metadata,occurred_at
           FROM rwa.audit_events
           WHERE tenant_id=$1 AND metadata->>'productId'=$2
           ORDER BY sequence_id`,
          [this.tenantId, productId],
        );
        view = {
          ...base,
          evidence,
          reconciliation,
          auditEvents: audit.rows.map((row) => ({
            sequence: Number(row.sequence_id),
            type: row.event_type,
            at: iso(row.occurred_at),
            productId,
            transactionId: row.aggregate_id,
            state: row.metadata.state ?? null,
            reasonCode: row.metadata.reasonCode ?? null,
          })),
          disclosureMode: "POSTGRESQL_METADATA_ONLY",
        };
      }
      await client.query("COMMIT");
      return view;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async #transactionForRole(queryable, { transactionId, role, actorRef = null }) {
    const result = await queryable.query(
      `SELECT t.id,t.tenant_id,t.product_id,t.transaction_type,t.current_state,t.settlement_rail,t.rule_version,
              t.nav_evidence_id,t.policy_snapshot_hash,t.private_payload_ciphertext,r.receipt,r.receipt_hash,
              z.finality_domain,z.finality_status,z.legal_register_applied,z.settled_at AS zk_settled_at,
              pj.state AS prover_job_state,pj.last_error_code AS prover_error_code
       FROM rwa.transaction_intents t
       LEFT JOIN rwa.transaction_receipts r ON r.transaction_id=t.id
       LEFT JOIN rwa.zk_settlements z ON z.transaction_id=t.id
       LEFT JOIN rwa.prover_jobs pj ON pj.transaction_id=t.id
       WHERE t.id=$1 AND t.tenant_id=$2`,
      [transactionId, this.tenantId],
    );
    if (result.rowCount !== 1) {
      const error = new Error("transaction not found");
      error.code = "UNKNOWN_TRANSACTION";
      throw error;
    }
    const row = result.rows[0];
    const metadata = {
      transactionId: row.id,
      productId: row.product_id,
      type: row.transaction_type,
      state: row.current_state,
      settlementRail: row.settlement_rail,
      finalityDomain: row.finality_domain,
      finalityStatus: row.finality_status,
      legalRegisterApplied: row.legal_register_applied,
      proverJobState: row.prover_job_state,
      proverErrorCode: row.prover_error_code,
      ruleVersion: row.rule_version,
      navEvidenceId: row.nav_evidence_id,
      policySnapshotHash: row.policy_snapshot_hash,
      receiptHash: row.receipt_hash,
      receipt: row.receipt,
    };

    if (METADATA_ROLES.has(role)) {
      return { ...metadata, disclosure: "METADATA_ONLY" };
    }
    if (!new Set(["broker", "investor"]).has(role)) denied("role cannot access transaction economics");

    const privatePayload = await this.payloadCipher.decrypt(row.private_payload_ciphertext, {
      tenantId: row.tenant_id,
      transactionId: row.id,
      productId: row.product_id,
      transactionType: row.transaction_type,
    });
    if (role === "investor") {
      if (!actorRef) denied("investor identity is required");
      const isParty = privatePayload.investorId === actorRef
        || privatePayload.sellerId === actorRef
        || privatePayload.buyerId === actorRef;
      if (!isParty) denied("investor is not a party to this transaction");
    }
    return {
      ...metadata,
      privatePayload,
      disclosure: role === "broker" ? "AUTHORIZED_BROKER_FULL" : "TRANSACTION_PARTY_ONLY",
    };
  }

  async #evidence(client, productId) {
    const result = await client.query(
      `SELECT id,data_type,source_institution_id,trust_tier,effective_at,expires_at,status
       FROM rwa.evidence_envelopes WHERE product_id=$1 ORDER BY effective_at,id`,
      [productId],
    );
    const now = this.now();
    return result.rows.map((row) => ({
      id: row.id,
      dataType: row.data_type,
      sourceInstitutionId: row.source_institution_id,
      trustTier: row.trust_tier,
      effectiveAt: iso(row.effective_at),
      expiresAt: iso(row.expires_at),
      status: new Date(row.effective_at) > now
        ? "PENDING"
        : new Date(row.expires_at) <= now
          ? "EXPIRED"
          : row.status,
    }));
  }

  async #transactionSummary(client, productId) {
    const result = await client.query(
      `SELECT t.id,t.transaction_type,t.current_state,t.settlement_rail,r.receipt,r.receipt_hash,
              z.finality_domain,z.finality_status,z.legal_register_applied,
              pj.state AS prover_job_state,pj.last_error_code AS prover_error_code
       FROM rwa.transaction_intents t
       LEFT JOIN rwa.transaction_receipts r ON r.transaction_id=t.id
       LEFT JOIN rwa.zk_settlements z ON z.transaction_id=t.id
       LEFT JOIN rwa.prover_jobs pj ON pj.transaction_id=t.id
       WHERE t.tenant_id=$1 AND t.product_id=$2 ORDER BY t.created_at,t.id`,
      [this.tenantId, productId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      type: row.transaction_type,
      state: row.current_state,
      settlementRail: row.settlement_rail,
      finalityDomain: row.finality_domain,
      finalityStatus: row.finality_status,
      legalRegisterApplied: row.legal_register_applied,
      proverJobState: row.prover_job_state,
      proverErrorCode: row.prover_error_code,
      settledAt: row.receipt?.settledAt ?? null,
      settlementMode: row.receipt?.settlementMode ?? null,
      receiptHash: row.receipt_hash,
      evidencePackageHash: null,
    }));
  }

  async #exceptions(client, productId) {
    const result = await client.query(
      `SELECT e.*,maker.decision AS proposed_decision,maker.actor_ref AS proposed_by,
              checker.actor_ref AS checked_by
       FROM rwa.exception_cases e
       JOIN rwa.transaction_intents t ON t.id=e.transaction_id AND t.tenant_id=$1
       LEFT JOIN rwa.approval_records maker
         ON maker.exception_id=e.id AND maker.approval_round=e.approval_round AND maker.role='MAKER'
       LEFT JOIN rwa.approval_records checker
         ON checker.exception_id=e.id AND checker.approval_round=e.approval_round AND checker.role='CHECKER'
       WHERE e.product_id=$2 ORDER BY e.opened_at,e.id`,
      [this.tenantId, productId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      status: row.status,
      failureStage: row.failure_stage,
      reasonCode: row.reason_code,
      openedAt: iso(row.opened_at),
      resolvedAt: iso(row.resolved_at),
      replacementTransactionId: row.replacement_transaction_id,
      proposedDecision: row.proposed_decision,
      proposedBy: row.proposed_by,
      checkedBy: row.checked_by,
    }));
  }

  async #accountBalance(client, table, productId, ownerRef, assetCode) {
    const prefix = table === "register" ? "register" : "ledger";
    const result = await client.query(
      `SELECT COALESCE(sum(e.signed_delta),0)::text AS balance
       FROM rwa.${prefix}_accounts a
       LEFT JOIN rwa.${prefix}_entries e ON e.account_id=a.id
       LEFT JOIN rwa.${prefix}_batches b ON b.id=e.batch_id AND b.status='POSTED'
       WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.owner_ref=$3 AND a.asset_code=$4
         AND (e.sequence_id IS NULL OR b.id IS NOT NULL)`,
      [this.tenantId, productId, ownerRef, assetCode],
    );
    return result.rows[0]?.balance ?? "0";
  }

  async #reconciliation(client, product) {
    const unitAsset = `UNIT:${product.id}`;
    const result = await client.query(
      `WITH asset AS (
         SELECT COALESCE(sum(e.signed_delta),0)::text AS units
         FROM rwa.ledger_accounts a
         JOIN rwa.ledger_entries e ON e.account_id=a.id
         JOIN rwa.ledger_batches b ON b.id=e.batch_id AND b.status='POSTED'
         WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.asset_code=$3 AND a.account_type='INVESTOR'
       ), register_total AS (
         SELECT COALESCE(sum(e.signed_delta),0)::text AS units
         FROM rwa.register_accounts a
         JOIN rwa.register_entries e ON e.account_id=a.id
         JOIN rwa.register_batches b ON b.id=e.batch_id AND b.status='POSTED'
         WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.asset_code=$3 AND a.account_type='INVESTOR'
       ), mismatches AS (
         WITH la AS (
           SELECT a.owner_ref,COALESCE(sum(e.signed_delta),0) AS balance
           FROM rwa.ledger_accounts a LEFT JOIN rwa.ledger_entries e ON e.account_id=a.id
           LEFT JOIN rwa.ledger_batches b ON b.id=e.batch_id AND b.status='POSTED'
           WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.asset_code=$3
             AND (e.sequence_id IS NULL OR b.id IS NOT NULL) GROUP BY a.owner_ref
         ), ra AS (
           SELECT a.owner_ref,COALESCE(sum(e.signed_delta),0) AS balance
           FROM rwa.register_accounts a LEFT JOIN rwa.register_entries e ON e.account_id=a.id
           LEFT JOIN rwa.register_batches b ON b.id=e.batch_id AND b.status='POSTED'
           WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.asset_code=$3
             AND (e.sequence_id IS NULL OR b.id IS NOT NULL) GROUP BY a.owner_ref
         )
         SELECT count(*)::int AS count FROM la FULL JOIN ra USING(owner_ref)
         WHERE la.balance IS DISTINCT FROM ra.balance
       ), controls AS (
         SELECT count(*) FILTER (WHERE t.current_state='SETTLED')::int AS expected,
                count(*) FILTER (WHERE t.current_state='SETTLED' AND c.state='CONFIRMED')::int AS confirmed
         FROM rwa.transaction_intents t LEFT JOIN rwa.cash_confirmations c ON c.transaction_id=t.id
         WHERE t.tenant_id=$1 AND t.product_id=$2
       ), exceptions AS (
         SELECT count(*)::int AS count FROM rwa.exception_cases e
         JOIN rwa.transaction_intents t ON t.id=e.transaction_id AND t.tenant_id=$1
         WHERE e.product_id=$2 AND e.status NOT LIKE 'RESOLVED_%'
       )
       SELECT asset.units AS asset_units,register_total.units AS register_units,
              mismatches.count AS mismatch_count,controls.expected,controls.confirmed,
              exceptions.count AS exception_count
       FROM asset,register_total,mismatches,controls,exceptions`,
      [this.tenantId, product.id, unitAsset],
    );
    const row = result.rows[0];
    const assetRegisterMatched = row.mismatch_count === 0;
    const cashConfirmed = row.expected === row.confirmed;
    const accountingControlsMatched = assetRegisterMatched && cashConfirmed;
    return {
      productId: product.id,
      confidentialAssetUnits: row.asset_units,
      legalRegisterUnits: row.register_units,
      assetRegisterMatched,
      cashExpectedCount: row.expected,
      cashConfirmedCount: row.confirmed,
      cashControlMode: "SANDBOX_JOURNAL_NOT_BANK_RECEIPT",
      cashConfirmed,
      openExceptionCount: row.exception_count,
      matched: accountingControlsMatched,
      overallStatus: !accountingControlsMatched
        ? "RECONCILIATION_EXCEPTION"
        : row.exception_count > 0
          ? "ATTENTION_REQUIRED"
          : "SANDBOX_CONTROLLED",
      checkedAt: this.now().toISOString(),
    };
  }
}
