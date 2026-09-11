import { createHash, sign, verify } from "node:crypto";

const SCHEMA = "rwa.institution-callback.v1";
const CHANNEL_ROLE = Object.freeze({ REGISTER: "transfer_agent", CASH: "cash_provider", CUSTODY: "custodian" });
const OUTCOMES = new Set(["CONFIRMED", "REJECTED", "PERMANENT_FAILURE"]);
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ASSET_CODE = /^[A-Za-z0-9][A-Za-z0-9:_-]{1,127}$/;
const CURRENCY = /^[A-Z]{3}$/;

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hash(value) {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalize(value)).digest("hex");
}

function unsigned(envelope) {
  const { signature: _signature, ...body } = envelope;
  return body;
}

function callbackError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function createSignedCallback(fields, privateKey) {
  const body = { schema: SCHEMA, ...fields };
  return { ...body, signature: sign(null, Buffer.from(canonicalize(body)), privateKey).toString("base64") };
}

export function verifyInstitutionCallbackSignature(envelope, publicKey) {
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(canonicalize(unsigned(envelope))),
      publicKey,
      Buffer.from(envelope?.signature ?? "", "base64"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw callbackError("INVALID_CALLBACK_SIGNATURE", "callback signature is invalid");
  return true;
}

export function validateInstitutionCallbackEnvelope(envelope, {
  now = new Date(), maxClockSkewMs = 300_000, maxValidityMs = 86_400_000,
  includeBusinessRules = true,
} = {}) {
  if (envelope?.schema !== SCHEMA) throw callbackError("UNSUPPORTED_CALLBACK_SCHEMA", "callback schema is unsupported");
  for (const field of ["callbackId", "tenantId", "institutionId", "productId", "channel", "eventType", "occurredAt", "expiresAt", "payloadHash", "signature"]) {
    if (typeof envelope[field] !== "string" || !envelope[field]) throw callbackError("INVALID_CALLBACK", `${field} is required`);
  }
  if (!CHANNEL_ROLE[envelope.channel]) throw callbackError("INVALID_CALLBACK_CHANNEL", "callback channel is unsupported");
  if (!Number.isSafeInteger(envelope.sequence) || envelope.sequence <= 0) throw callbackError("INVALID_CALLBACK_SEQUENCE", "callback sequence must be positive");
  if (!envelope.payload || typeof envelope.payload !== "object" || Array.isArray(envelope.payload)) throw callbackError("INVALID_CALLBACK_PAYLOAD", "callback payload is required");
  if (!OUTCOMES.has(envelope.payload.outcome) || typeof envelope.payload.subjectRef !== "string") {
    throw callbackError("INVALID_CALLBACK_PAYLOAD", "callback outcome and subjectRef are required");
  }
  if (hash(envelope.payload) !== envelope.payloadHash) throw callbackError("CALLBACK_PAYLOAD_TAMPERED", "callback payload hash mismatch");
  const occurredAt = new Date(envelope.occurredAt);
  const expiresAt = new Date(envelope.expiresAt);
  const currentTime = new Date(now);
  if (!Number.isFinite(currentTime.getTime())) throw callbackError("INVALID_CALLBACK_TIME", "verifier time is invalid");
  if (!Number.isFinite(occurredAt.getTime()) || !Number.isFinite(expiresAt.getTime()) || expiresAt <= occurredAt) {
    throw callbackError("INVALID_CALLBACK_TIME", "callback time window is invalid");
  }
  if (occurredAt.getTime() - currentTime.getTime() > maxClockSkewMs) throw callbackError("CALLBACK_FROM_FUTURE", "callback occurredAt is too far in the future");
  if (currentTime >= expiresAt) throw callbackError("CALLBACK_EXPIRED", "callback has expired");
  if (expiresAt.getTime() - occurredAt.getTime() > maxValidityMs) throw callbackError("CALLBACK_VALIDITY_TOO_LONG", "callback validity window is too long");

  const result = { schema: SCHEMA, channel: envelope.channel, requiredRole: CHANNEL_ROLE[envelope.channel] };
  if (!includeBusinessRules) return result;

  const payload = envelope.payload;
  if (envelope.eventType !== `${envelope.channel}.${payload.outcome}`) {
    throw callbackError("CALLBACK_EVENT_OUTCOME_MISMATCH", "eventType must match channel and outcome");
  }
  const expectedSubjectType = envelope.channel === "CUSTODY" ? "POSITION" : "TRANSACTION";
  if (payload.subjectType !== expectedSubjectType) throw callbackError("INVALID_CALLBACK_SUBJECT", `${envelope.channel} requires ${expectedSubjectType}`);
  const allowedPayload = new Set(["subjectType", "subjectRef", "outcome", "details"]);
  if (Object.keys(payload).some((key) => !allowedPayload.has(key)) || !payload.details || typeof payload.details !== "object" || Array.isArray(payload.details)) {
    throw callbackError("INVALID_CALLBACK_PAYLOAD", "callback payload contains unsupported fields");
  }
  const rules = {
    REGISTER: {
      fields: ["registerReference", "assetCode", "units", "registerVersion"],
      validate: (d) => typeof d.registerReference === "string" && ASSET_CODE.test(d.assetCode)
        && DECIMAL.test(d.units) && d.units !== "0" && Number.isSafeInteger(d.registerVersion) && d.registerVersion > 0,
    },
    CASH: {
      fields: ["bankReference", "currency", "amountMinor", "feeMinor"],
      validate: (d) => typeof d.bankReference === "string" && CURRENCY.test(d.currency)
        && DECIMAL.test(d.amountMinor) && d.amountMinor !== "0" && DECIMAL.test(d.feeMinor),
    },
    CUSTODY: {
      fields: ["statementId", "assetCode", "balanceUnits", "asOf"],
      validate: (d) => typeof d.statementId === "string" && ASSET_CODE.test(d.assetCode)
        && DECIMAL.test(d.balanceUnits) && Number.isFinite(new Date(d.asOf).getTime()),
    },
  }[envelope.channel];
  if (Object.keys(payload.details).length !== rules.fields.length
    || rules.fields.some((field) => !(field in payload.details)) || !rules.validate(payload.details)) {
    throw callbackError("INVALID_CALLBACK_PAYLOAD", `${envelope.channel} callback details do not match schema`);
  }
  return result;
}

export class InstitutionCallbackService {
  constructor(store, {
    tenantId, now = () => new Date(), maxClockSkewMs = 300_000, maxValidityMs = 86_400_000,
    economicCommitter = null,
  } = {}) {
    if (typeof tenantId !== "string" || tenantId.length < 1 || tenantId.length > 200) {
      throw callbackError("CALLBACK_TENANT_REQUIRED", "institution callback service requires one bounded tenant scope");
    }
    this.store = store;
    this.tenantId = tenantId;
    this.now = now;
    this.maxClockSkewMs = maxClockSkewMs;
    this.maxValidityMs = maxValidityMs;
    this.economicCommitter = economicCommitter;
  }

  async receive(envelope) {
    validateInstitutionCallbackEnvelope(envelope, {
      now: this.now(), maxClockSkewMs: this.maxClockSkewMs, maxValidityMs: this.maxValidityMs,
      includeBusinessRules: false,
    });
    if (envelope.tenantId !== this.tenantId) {
      throw callbackError("CALLBACK_TENANT_MISMATCH", "callback is outside this service tenant scope");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const institution = await client.query(
        "SELECT status,public_key_pem FROM rwa.institutions WHERE id=$1 FOR SHARE",
        [envelope.institutionId],
      );
      if (institution.rowCount !== 1 || institution.rows[0].status !== "ACTIVE") {
        throw callbackError("UNTRUSTED_CALLBACK_SOURCE", "callback institution is not active");
      }
      const role = CHANNEL_ROLE[envelope.channel];
      const assignment = await client.query(
        `SELECT 1 FROM rwa.product_role_assignments
         WHERE product_id=$1 AND role=$2 AND institution_id=$3 AND ended_at IS NULL`,
        [envelope.productId, role, envelope.institutionId],
      );
      if (assignment.rowCount !== 1) throw callbackError("UNAUTHORIZED_CALLBACK_SOURCE", `callback requires assigned ${role}`);
      verifyInstitutionCallbackSignature(envelope, institution.rows[0].public_key_pem);
      validateInstitutionCallbackEnvelope(envelope, {
        now: this.now(), maxClockSkewMs: this.maxClockSkewMs, maxValidityMs: this.maxValidityMs,
      });

      const envelopeHash = hash(unsigned(envelope));
      const duplicate = await client.query(
        `SELECT r.envelope_hash,a.status,a.outcome FROM rwa.callback_receipts r
         JOIN rwa.callback_applications a USING(callback_id) WHERE r.callback_id=$1`,
        [envelope.callbackId],
      );
      if (duplicate.rowCount === 1) {
        if (duplicate.rows[0].envelope_hash !== envelopeHash) {
          throw callbackError("CALLBACK_ID_CONFLICT", "callback id was reused with different content");
        }
        return { callbackId: envelope.callbackId, duplicate: true, status: duplicate.rows[0].status, outcome: duplicate.rows[0].outcome };
      }

      await client.query(
        `INSERT INTO rwa.callback_stream_positions(tenant_id,institution_id,product_id,channel)
         VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
        [envelope.tenantId, envelope.institutionId, envelope.productId, envelope.channel],
      );
      const position = await client.query(
        `SELECT next_sequence FROM rwa.callback_stream_positions
         WHERE tenant_id=$1 AND institution_id=$2 AND product_id=$3 AND channel=$4 FOR UPDATE`,
        [envelope.tenantId, envelope.institutionId, envelope.productId, envelope.channel],
      );
      const expected = Number(position.rows[0].next_sequence);
      if (envelope.sequence < expected) throw callbackError("CALLBACK_SEQUENCE_CONFLICT", "callback sequence is already consumed");

      try {
        await client.query(
          `INSERT INTO rwa.callback_receipts
           (callback_id,tenant_id,institution_id,product_id,channel,stream_sequence,event_type,
            occurred_at,expires_at,payload,payload_hash,envelope_hash,signature)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`,
          [envelope.callbackId, envelope.tenantId, envelope.institutionId, envelope.productId,
            envelope.channel, envelope.sequence, envelope.eventType, envelope.occurredAt, envelope.expiresAt,
            JSON.stringify(envelope.payload), envelope.payloadHash, envelopeHash, envelope.signature],
        );
      } catch (error) {
        if (error.code === "23505") throw callbackError("CALLBACK_SEQUENCE_CONFLICT", "callback stream sequence already exists");
        throw error;
      }
      const initialStatus = envelope.sequence === expected ? "APPLIED" : "BUFFERED";
      if (initialStatus === "BUFFERED") {
        await client.query("INSERT INTO rwa.callback_applications(callback_id,status) VALUES ($1,'BUFFERED')", [envelope.callbackId]);
        return { callbackId: envelope.callbackId, duplicate: false, status: "BUFFERED", expectedSequence: expected };
      }

      await this.#apply(client, envelope.callbackId, envelope);
      let nextSequence = expected + 1;
      let drained = 0;
      while (true) {
        const next = await client.query(
          `SELECT r.callback_id,r.payload FROM rwa.callback_receipts r
           JOIN rwa.callback_applications a USING(callback_id)
           WHERE r.tenant_id=$1 AND r.institution_id=$2 AND r.product_id=$3 AND r.channel=$4
             AND r.stream_sequence=$5 AND a.status='BUFFERED'`,
          [envelope.tenantId, envelope.institutionId, envelope.productId, envelope.channel, nextSequence],
        );
        if (next.rowCount === 0) break;
        const bufferedEnvelope = await client.query("SELECT * FROM rwa.callback_receipts WHERE callback_id=$1", [next.rows[0].callback_id]);
        await this.#apply(client, next.rows[0].callback_id, this.#fromReceipt(bufferedEnvelope.rows[0]), { buffered: true });
        nextSequence += 1;
        drained += 1;
      }
      await client.query(
        `UPDATE rwa.callback_stream_positions SET next_sequence=$5,updated_at=clock_timestamp()
         WHERE tenant_id=$1 AND institution_id=$2 AND product_id=$3 AND channel=$4`,
        [envelope.tenantId, envelope.institutionId, envelope.productId, envelope.channel, nextSequence],
      );
      return { callbackId: envelope.callbackId, duplicate: false, status: "APPLIED", outcome: envelope.payload.outcome, drained };
    });
  }

  async #apply(client, callbackId, envelope, { buffered = false } = {}) {
    const payload = envelope.payload;
    if (buffered) {
      await client.query(
        `UPDATE rwa.callback_applications
         SET status='APPLIED',outcome=$2,applied_at=clock_timestamp() WHERE callback_id=$1`,
        [callbackId, payload.outcome],
      );
    } else {
      await client.query(
        `INSERT INTO rwa.callback_applications(callback_id,status,outcome,applied_at)
         VALUES ($1,'APPLIED',$2,clock_timestamp())`,
        [callbackId, payload.outcome],
      );
    }
    await client.query(
      `INSERT INTO rwa.callback_effects(callback_id,subject_ref,outcome,details)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [callbackId, payload.subjectRef, payload.outcome, JSON.stringify(payload.details ?? {})],
    );
    await this.#recordEvidenceAndReconciliation(client, envelope);
  }

  #fromReceipt(row) {
    return {
      callbackId: row.callback_id, tenantId: row.tenant_id, institutionId: row.institution_id,
      productId: row.product_id, channel: row.channel, sequence: Number(row.stream_sequence),
      eventType: row.event_type, occurredAt: new Date(row.occurred_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(), payload: row.payload,
      payloadHash: row.payload_hash, signature: row.signature,
    };
  }

  async #recordEvidenceAndReconciliation(client, envelope) {
    const payload = envelope.payload;
    const evidenceId = `callback:${envelope.callbackId}`;
    const evidenceType = { REGISTER: "legal_register", CASH: "cash_state", CUSTODY: "custody_balance" }[envelope.channel];
    await client.query(
      `INSERT INTO rwa.callback_evidence_records
       (callback_id,evidence_id,product_id,evidence_type,source_institution_id,subject_type,subject_ref,
        payload,payload_hash,source_signature,effective_at,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12)`,
      [envelope.callbackId, evidenceId, envelope.productId, evidenceType, envelope.institutionId,
        payload.subjectType, payload.subjectRef, JSON.stringify(payload), envelope.payloadHash,
        envelope.signature, envelope.occurredAt, envelope.expiresAt],
    );
    let transactionId = null;
    let reconciliationStatus = "NOT_APPLICABLE";
    let mismatchReason = null;
    if (payload.subjectType === "TRANSACTION") {
      const transaction = await client.query(
        `SELECT id,tenant_id,product_id,transaction_type,private_payload_ciphertext
         FROM rwa.transaction_intents WHERE id=$1`,
        [payload.subjectRef],
      );
      transactionId = transaction.rows[0]?.id ?? null;
      if (!transactionId) {
        reconciliationStatus = "MISMATCH";
        mismatchReason = "UNKNOWN_TRANSACTION";
      } else if (transaction.rows[0].tenant_id !== envelope.tenantId || transaction.rows[0].product_id !== envelope.productId) {
        reconciliationStatus = "MISMATCH";
        mismatchReason = "TRANSACTION_CONTEXT_MISMATCH";
      } else {
        const product = await client.query("SELECT currency FROM rwa.products WHERE id=$1", [envelope.productId]);
        const expectedAsset = `UNIT:${envelope.productId}`;
        if (envelope.channel === "CASH" && payload.details.currency !== product.rows[0].currency) {
          reconciliationStatus = "MISMATCH";
          mismatchReason = "CURRENCY_MISMATCH";
        } else if (envelope.channel === "REGISTER" && payload.details.assetCode !== expectedAsset) {
          reconciliationStatus = "MISMATCH";
          mismatchReason = "ASSET_MISMATCH";
        } else {
          reconciliationStatus = "CONTEXT_MATCHED";
          const commitment = await client.query(
            "SELECT * FROM rwa.transaction_economic_commitments WHERE transaction_id=$1",
            [transactionId],
          );
          if (!this.economicCommitter || commitment.rowCount !== 1) {
            reconciliationStatus = "MISMATCH";
            mismatchReason = "MISSING_ECONOMIC_COMMITMENT";
          } else {
            const row = commitment.rows[0];
            const context = { tenantId: envelope.tenantId, transactionId, productId: envelope.productId };
            const checks = envelope.channel === "REGISTER"
              ? [["units", payload.details.units, row.units_commitment]]
              : [
                ["cashAmountMinor", payload.details.amountMinor, row.cash_amount_commitment],
                ["feeAmountMinor", payload.details.feeMinor, row.fee_amount_commitment],
              ];
            const matched = await Promise.all(checks.map(([field, value, expected]) => (
              this.economicCommitter.matches({ ...context, field, value }, expected, row.key_id)
            )));
            if (matched.every(Boolean)) {
              reconciliationStatus = "FULLY_MATCHED";
            } else {
              reconciliationStatus = "MISMATCH";
              mismatchReason = envelope.channel === "REGISTER" ? "UNITS_COMMITMENT_MISMATCH" : "CASH_COMMITMENT_MISMATCH";
            }
          }
        }
      }
    }
    await client.query(
      `INSERT INTO rwa.external_callback_confirmations
       (callback_id,transaction_id,product_id,channel,outcome,reconciliation_status,mismatch_reason,evidence_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [envelope.callbackId, transactionId, envelope.productId, envelope.channel, payload.outcome,
        reconciliationStatus, mismatchReason, evidenceId],
    );
    if (reconciliationStatus === "MISMATCH" || payload.outcome !== "CONFIRMED") {
      const incidentId = `external-incident:${envelope.callbackId}`;
      const reasonCode = mismatchReason ?? `EXTERNAL_${envelope.channel}_${payload.outcome}`;
      const severity = payload.outcome === "PERMANENT_FAILURE" ? "CRITICAL" : "HIGH";
      await client.query(
        `INSERT INTO rwa.external_reconciliation_incidents
         (id,callback_id,transaction_id,tenant_id,product_id,channel,severity,reason_code)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [incidentId, envelope.callbackId, transactionId, envelope.tenantId, envelope.productId,
          envelope.channel, severity, reasonCode],
      );
      await this.store.recordAuditEvent(client, {
        tenantId: envelope.tenantId, eventType: "external_incident.opened",
        aggregateType: "external_incident", aggregateId: incidentId,
        metadata: { incidentId, callbackId: envelope.callbackId, transactionId, channel: envelope.channel, severity, reasonCode },
      });
      await this.store.enqueueOutbox(client, {
        tenantId: envelope.tenantId, topic: "rwa.external_incident.opened", aggregateId: incidentId,
        payload: { incidentId, callbackId: envelope.callbackId, transactionId, channel: envelope.channel, severity, reasonCode },
      });
    }
  }
}

export function callbackPayloadHash(payload) {
  return hash(payload);
}
