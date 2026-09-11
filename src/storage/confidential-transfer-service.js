import { randomUUID } from "node:crypto";
import { normalizeFieldElement } from "../security/proof-adapter.js";
import { sha256Canonical } from "./postgres-store.js";
import { assertEligibleCredential, assertRegisteredRecipientKey } from "./confidential-eligibility.js";

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
    senderInvestorId,
    senderCredentialId,
    recipientInvestorId,
    recipientCredentialId,
    originatingInstitutionId,
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
    if (typeof originatingInstitutionId !== "string" || originatingInstitutionId.length < 1 || originatingInstitutionId.length > 200) {
      throw serviceError("AUTHORIZATION_DENIED", "confidential transfers must be originated by an institution member");
    }
    const parties = { senderInvestorId, senderCredentialId, recipientInvestorId, recipientCredentialId };
    for (const [label, value] of Object.entries(parties)) {
      if (typeof value !== "string" || value.length < 1 || value.length > 200) {
        throw serviceError("INVALID_CONFIDENTIAL_INSTRUCTION", `${label} is required for an eligible confidential transfer`);
      }
    }
    const request = {
      operation: "CONFIDENTIAL_JOIN_SPLIT_TRANSFER",
      transactionId,
      productId,
      fee: normalizedFee,
      recipient: normalizedRecipient,
      relayer: normalizedRelayer,
      expiresAt: expiry.toISOString(),
      ...parties,
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
      await assertEligibleCredential(client, {
        productId, rules: row.rules, now, party: "sender",
        subjectRef: senderInvestorId, credentialId: senderCredentialId,
      });
      await assertEligibleCredential(client, {
        productId, rules: row.rules, now, party: "recipient",
        subjectRef: recipientInvestorId, credentialId: recipientCredentialId,
      });
      await assertRegisteredRecipientKey(client, {
        productId, ownerPublicKey: normalizedRecipient,
        subjectRef: recipientInvestorId, credentialId: recipientCredentialId,
      });
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
        originatingInstitutionId,
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
         (transaction_id,tenant_id,request_hash,fee,recipient,relayer,authorized_by,expires_at,
          sender_subject_ref,sender_credential_id,recipient_subject_ref,recipient_credential_id)
         VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7,$8,$9,$10,$11,$12)`,
        [transactionId, tenantId, created.transaction.request_hash, normalizedFee,
          normalizedRecipient, normalizedRelayer, authorizedBy, expiry.toISOString(),
          senderInvestorId, senderCredentialId, recipientInvestorId, recipientCredentialId],
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

  async registerOwnerKey({ tenantId = this.tenantId, productId, subjectRef, credentialId, ownerPublicKey, registeredBy, actorInstitutionId }) {
    if (tenantId !== this.tenantId) {
      throw serviceError("TENANT_SCOPE_MISMATCH", "note owner key tenant is outside this runtime scope");
    }
    for (const [label, value] of Object.entries({ productId, subjectRef, credentialId, registeredBy, actorInstitutionId })) {
      if (typeof value !== "string" || value.length < 1 || value.length > 200) {
        throw serviceError("INVALID_NOTE_OWNER_KEY", `${label} must be a bounded non-empty string`);
      }
    }
    const normalizedKey = instructionField(ownerPublicKey, "ownerPublicKey");
    if (normalizedKey === "0") throw serviceError("INVALID_NOTE_OWNER_KEY", "owner public key cannot be zero");
    return this.store.withSerializableTransaction(async (client) => {
      const product = await client.query(
        `SELECT p.rules FROM rwa.products p WHERE p.id=$1 AND EXISTS (
           SELECT 1 FROM rwa.ledger_accounts a WHERE a.product_id=p.id AND a.tenant_id=$2) FOR SHARE`,
        [productId, tenantId],
      );
      if (product.rowCount !== 1) throw serviceError("UNKNOWN_PRODUCT", "product not found for tenant");
      const onboarding = await client.query(
        `SELECT 1 FROM rwa.product_role_assignments
         WHERE product_id=$1 AND institution_id=$2 AND role IN ('distributor','credential_issuer') AND ended_at IS NULL`,
        [productId, actorInstitutionId],
      );
      if (onboarding.rowCount === 0) {
        throw serviceError("AUTHORIZATION_DENIED", "only the product's assigned distributor or credential issuer can register note owner keys");
      }
      await assertEligibleCredential(client, {
        productId, rules: product.rows[0].rules, now: this.now(), party: "note owner", subjectRef, credentialId,
      });
      try {
        await client.query(
          `INSERT INTO rwa.confidential_note_owner_keys
           (product_id,owner_public_key,subject_ref,credential_id,status,registered_by)
           VALUES ($1,$2::numeric,$3,$4,'ACTIVE',$5)`,
          [productId, normalizedKey, subjectRef, credentialId, registeredBy],
        );
      } catch (cause) {
        if (cause.code === "23505") throw serviceError("NOTE_OWNER_KEY_ALREADY_REGISTERED", "owner public key is already registered for this product", cause);
        throw cause;
      }
      const metadata = { productId, credentialId, subjectRefHash: sha256Canonical(subjectRef), registeredBy, status: "ACTIVE" };
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.note_owner_key.registered", aggregateType: "credential", aggregateId: credentialId, metadata,
      });
      return { productId, credentialId, ownerPublicKey: normalizedKey, status: "ACTIVE" };
    });
  }

  async revokeOwnerKey({ tenantId = this.tenantId, productId, ownerPublicKey, revokedBy, reason }) {
    if (tenantId !== this.tenantId) {
      throw serviceError("TENANT_SCOPE_MISMATCH", "note owner key tenant is outside this runtime scope");
    }
    for (const [label, value] of Object.entries({ productId, revokedBy, reason })) {
      if (typeof value !== "string" || value.length < 1 || value.length > 1000) {
        throw serviceError("INVALID_NOTE_OWNER_KEY", `${label} must be a bounded non-empty string`);
      }
    }
    const normalizedKey = instructionField(ownerPublicKey, "ownerPublicKey");
    return this.store.withSerializableTransaction(async (client) => {
      const updated = await client.query(
        `UPDATE rwa.confidential_note_owner_keys k
         SET status='REVOKED',revoked_by=$3,revoked_at=clock_timestamp(),revoke_reason=$4
         WHERE k.product_id=$1 AND k.owner_public_key=$2::numeric AND k.status='ACTIVE'
           AND EXISTS (SELECT 1 FROM rwa.ledger_accounts a WHERE a.product_id=k.product_id AND a.tenant_id=$5)
         RETURNING credential_id`,
        [productId, normalizedKey, revokedBy, reason, tenantId],
      );
      if (updated.rowCount !== 1) throw serviceError("NOTE_OWNER_KEY_NOT_ACTIVE", "owner public key is not active for this product");
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.note_owner_key.revoked", aggregateType: "credential",
        aggregateId: updated.rows[0].credential_id, metadata: { productId, revokedBy, reason, status: "REVOKED" },
      });
      return { productId, ownerPublicKey: normalizedKey, status: "REVOKED" };
    });
  }
}
