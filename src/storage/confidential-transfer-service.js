import { randomUUID } from "node:crypto";
import { normalizeFieldElement } from "../security/proof-adapter.js";
import { sha256Canonical } from "./postgres-store.js";

const UINT64_LIMIT = 18446744073709551616n;

function serviceError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function instructionField(value, label) {
  try { return normalizeFieldElement(String(value ?? ""), label); }
  catch (cause) { throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", cause.message, cause); }
}

export class ConfidentialTransferService {
  constructor(store, {
    payloadCipher,
    circuitId,
    circuitVersion,
    tenantId = "sandbox-hk",
    now = () => new Date(),
  } = {}) {
    if (!payloadCipher || typeof payloadCipher.encrypt !== "function") {
      throw serviceError("PAYLOAD_CIPHER_REQUIRED", "confidential transfer preparation requires payload encryption");
    }
    if (!circuitId || !circuitVersion) {
      throw serviceError("PROOF_CIRCUIT_REQUIRED", "confidential transfer preparation requires a pinned circuit version");
    }
    this.store = store;
    this.payloadCipher = payloadCipher;
    this.circuitId = circuitId;
    this.circuitVersion = circuitVersion;
    this.tenantId = tenantId;
    this.now = now;
  }

  async prepare({
    transactionId = `zk-transfer:${randomUUID()}`,
    idempotencyKey,
    productId,
    fee,
    recipient,
    relayer,
    authorizedBy,
    tenantId = this.tenantId,
    expiresAt,
  }) {
    if (tenantId !== this.tenantId) {
      throw serviceError("TENANT_SCOPE_MISMATCH", "confidential transfer tenant is outside this runtime scope");
    }
    if (!idempotencyKey || typeof idempotencyKey !== "string" || idempotencyKey.length > 200) {
      throw serviceError("INVALID_IDEMPOTENCY_KEY", "a bounded idempotency key is required");
    }
    if (typeof transactionId !== "string" || transactionId.length < 1 || transactionId.length > 200
        || typeof productId !== "string" || productId.length < 1 || productId.length > 200
        || typeof authorizedBy !== "string" || authorizedBy.length < 1 || authorizedBy.length > 200) {
      throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", "product and server-authorized actor are required");
    }
    const expiry = new Date(expiresAt);
    const now = this.now();
    if (!expiresAt || Number.isNaN(expiry.getTime()) || expiry <= now
        || expiry.getTime() - now.getTime() > 24 * 60 * 60 * 1000) {
      throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", "expiry must be in the future and no more than 24 hours away");
    }
    const normalizedFee = instructionField(fee, "fee");
    const normalizedRecipient = instructionField(recipient, "recipient");
    const normalizedRelayer = instructionField(relayer, "relayer");
    if (BigInt(normalizedFee) >= UINT64_LIMIT) {
      throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", "fee must fit in an unsigned 64-bit integer");
    }
    if (normalizedRecipient === "0") {
      throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", "recipient cannot be the zero field element");
    }
    const request = {
      operation: "CONFIDENTIAL_JOIN_SPLIT_TRANSFER",
      transactionId,
      productId,
      fee: normalizedFee,
      recipient: normalizedRecipient,
      relayer: normalizedRelayer,
      expiresAt: expiry.toISOString(),
    };

    return this.store.withSerializableTransaction(async (client) => {
      const policy = await client.query(
        `SELECT p.rule_version,p.rules,z.context_id,z.asset_type
         FROM rwa.products p
         JOIN rwa.zk_product_contexts z ON z.product_id=p.id AND z.retired_at IS NULL
         JOIN rwa.proof_circuit_versions c
           ON c.circuit_id=z.circuit_id AND c.circuit_version=z.circuit_version
         WHERE p.id=$1 AND p.status='ACTIVE'
           AND z.circuit_id=$2 AND z.circuit_version=$3 AND c.status='ACTIVE'
           AND EXISTS (
             SELECT 1 FROM rwa.ledger_accounts a
             WHERE a.product_id=p.id AND a.tenant_id=$4
           )
         FOR SHARE OF p,z,c`,
        [productId, this.circuitId, this.circuitVersion, tenantId],
      );
      if (policy.rowCount !== 1) {
        throw serviceError("UNAPPROVED_PROOF_CONTEXT", "product has no active context for the pinned proof circuit");
      }
      const row = policy.rows[0];
      const policySnapshotHash = sha256Canonical({
        ruleVersion: row.rule_version,
        rules: row.rules,
        circuitId: this.circuitId,
        circuitVersion: this.circuitVersion,
        contextId: row.context_id,
        assetType: row.asset_type,
      });
      const created = await this.store.createTransactionIntent(client, {
        id: transactionId,
        tenantId,
        productId,
        idempotencyKey,
        request,
        transactionType: "TRANSFER",
        settlementRail: "CONFIDENTIAL_NOTE",
        ruleVersion: row.rule_version,
        navEvidenceId: null,
        policySnapshotHash,
        privatePayloadCiphertext: await this.payloadCipher.encrypt(request, {
          tenantId,
          transactionId,
          productId,
          transactionType: "TRANSFER",
        }),
        actorRef: authorizedBy,
      });
      if (!created.created) {
        const existing = await client.query(
          `SELECT t.current_state,t.settlement_rail,i.fee::text,i.recipient::text,i.relayer::text,i.expires_at
           FROM rwa.transaction_intents t
           JOIN rwa.zk_execution_instructions i ON i.transaction_id=t.id
           WHERE t.id=$1 FOR SHARE OF i`,
          [created.transaction.id],
        );
        if (existing.rowCount !== 1 || existing.rows[0].settlement_rail !== "CONFIDENTIAL_NOTE") {
          throw serviceError("IDEMPOTENCY_INTEGRITY_FAILURE", "existing idempotent transaction is not a confidential transfer");
        }
        return {
          transactionId: created.transaction.id,
          state: existing.rows[0].current_state,
          settlementRail: existing.rows[0].settlement_rail,
          contextId: row.context_id,
          assetType: row.asset_type,
          expiresAt: existing.rows[0].expires_at.toISOString(),
          created: false,
        };
      }

      await client.query(
        `INSERT INTO rwa.zk_execution_instructions
         (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by,expires_at)
         VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7,$8)`,
        [transactionId, tenantId, created.transaction.request_hash, normalizedFee,
          normalizedRecipient, normalizedRelayer, authorizedBy, expiry.toISOString()],
      );
      await this.store.transitionTransaction(client, {
        transactionId, toState: "POLICY_CHECKED", actorRef: authorizedBy,
      });
      await this.store.transitionTransaction(client, {
        transactionId, toState: "PROOF_PENDING", actorRef: authorizedBy,
      });
      const metadata = {
        productId,
        state: "PROOF_PENDING",
        settlementRail: "CONFIDENTIAL_NOTE",
        contextId: row.context_id,
        assetType: row.asset_type,
        circuitId: this.circuitId,
        circuitVersion: this.circuitVersion,
        expiresAt: expiry.toISOString(),
        legalRegisterApplied: false,
      };
      await this.store.recordAuditEvent(client, {
        tenantId,
        eventType: "zk.confidential_transfer.prepared",
        aggregateType: "transaction",
        aggregateId: transactionId,
        metadata,
      });
      await this.store.enqueueOutbox(client, {
        tenantId,
        topic: "rwa.zk.confidential_transfer.prepared",
        aggregateId: transactionId,
        payload: { transactionId, ...metadata },
      });
      return { transactionId, ...metadata, created: true };
    });
  }
}
