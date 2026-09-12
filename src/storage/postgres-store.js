import { createHash, randomUUID } from "node:crypto";
import { auditChainLockKey } from "./audit-checkpoint-service.js";

const TRANSITIONS = new Map([
  ["REQUESTED", new Set(["POLICY_CHECKED", "REJECTED"])],
  ["POLICY_CHECKED", new Set(["CASH_RESERVED", "PROOF_PENDING", "REJECTED"])],
  ["CASH_RESERVED", new Set(["REGISTER_PENDING", "REQUIRES_REVIEW", "REJECTED"])],
  ["REGISTER_PENDING", new Set(["SETTLED", "REQUIRES_REVIEW", "REJECTED"])],
  ["PROOF_PENDING", new Set(["ROOT_PENDING", "REQUIRES_REVIEW", "REJECTED"])],
  // Nullifiers are already spent: the only exit is verified root finality (M2).
  ["ROOT_PENDING", new Set(["SETTLED"])],
  ["REQUIRES_REVIEW", new Set(["PENDING_APPROVAL", "CANCELLED"])],
  ["PENDING_APPROVAL", new Set(["REQUIRES_REVIEW", "REPLACED", "CANCELLED"])],
]);

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256Canonical(value) {
  return createHash("sha256").update(canonicalize(value)).digest("hex");
}

export function assertTransition(fromState, toState) {
  if (!TRANSITIONS.get(fromState)?.has(toState)) {
    const error = new Error(`invalid transaction transition ${fromState} -> ${toState}`);
    error.code = "INVALID_STATE_TRANSITION";
    throw error;
  }
}

export function assertBalancedEntries(entries) {
  if (!Array.isArray(entries) || entries.length < 2) {
    const error = new Error("a ledger batch requires at least two entries");
    error.code = "INVALID_LEDGER_BATCH";
    throw error;
  }
  const totals = new Map();
  for (const entry of entries) {
    const delta = BigInt(entry.signedDelta);
    if (delta === 0n) {
      const error = new Error("ledger entries cannot be zero");
      error.code = "INVALID_LEDGER_ENTRY";
      throw error;
    }
    totals.set(entry.assetCode, (totals.get(entry.assetCode) ?? 0n) + delta);
  }
  for (const [assetCode, total] of totals) {
    if (total !== 0n) {
      const error = new Error(`unbalanced ledger asset ${assetCode}`);
      error.code = "UNBALANCED_LEDGER_BATCH";
      throw error;
    }
  }
}

export class PostgresStore {
  constructor(pool) {
    this.pool = pool;
  }

  static async connect({ connectionString, max = 10 }) {
    const { Pool } = await import("pg");
    const pool = new Pool({ connectionString, max, application_name: "rwa-control-plane" });
    // An idle pooled connection killed by a database restart or failover is
    // reported on the pool. Without a listener Node treats it as an uncaught
    // exception and the whole process exits; the pool already discards the
    // broken client and the next checkout reconnects.
    pool.on("error", (error) => {
      console.error("PostgreSQL idle client error", { code: error?.code ?? "UNKNOWN", message: error?.message });
    });
    return new PostgresStore(pool);
  }

  async close() {
    await this.pool.end();
  }

  async withSerializableTransaction(operation, { retries = 3 } = {}) {
    for (let attempt = 1; attempt <= retries; attempt += 1) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const result = await operation(client);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        if (!["40001", "40P01"].includes(error.code) || attempt === retries) throw error;
      } finally {
        client.release();
      }
    }
    throw new Error("serializable transaction retry exhausted");
  }

  async withReadCommittedTransaction(operation) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async createTransactionIntent(client, intent) {
    const requestHash = sha256Canonical(intent.request);
    const result = await client.query(
      `INSERT INTO rwa.transaction_intents
       (id, tenant_id, product_id, idempotency_key, request_hash, transaction_type, current_state,
        rule_version, nav_evidence_id, policy_snapshot_hash, private_payload_ciphertext, settlement_rail,
        originating_institution_id, party_index_key_id)
       VALUES ($1,$2,$3,$4,$5,$6,'REQUESTED',$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
       RETURNING *`,
      [intent.id, intent.tenantId, intent.productId, intent.idempotencyKey, requestHash,
        intent.transactionType, intent.ruleVersion, intent.navEvidenceId, intent.policySnapshotHash,
        intent.privatePayloadCiphertext, intent.settlementRail ?? "REGISTERED",
        intent.originatingInstitutionId ?? null, intent.partyIndex?.keyId ?? null],
    );
    if (result.rowCount === 1) {
      for (const partyMac of intent.partyIndex?.macs ?? []) {
        await client.query(
          `INSERT INTO rwa.transaction_party_index(transaction_id,tenant_id,product_id,party_mac)
           VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
          [intent.id, intent.tenantId, intent.productId, partyMac],
        );
      }
      await client.query(
        `INSERT INTO rwa.transaction_state_history(transaction_id, from_state, to_state, actor_ref)
         VALUES ($1,NULL,'REQUESTED',$2)`,
        [intent.id, intent.actorRef],
      );
      return { created: true, transaction: result.rows[0] };
    }
    const existing = await client.query(
      `SELECT * FROM rwa.transaction_intents WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
      [intent.tenantId, intent.idempotencyKey],
    );
    if (existing.rows[0]?.request_hash !== requestHash
        || (intent.originatingInstitutionId !== undefined
          && existing.rows[0]?.originating_institution_id !== (intent.originatingInstitutionId ?? null))) {
      const error = new Error("idempotency key reused for a different request");
      error.code = "IDEMPOTENCY_CONFLICT";
      throw error;
    }
    return { created: false, transaction: existing.rows[0] };
  }

  async transitionTransaction(client, { transactionId, toState, reasonCode = null, actorRef = null }) {
    const locked = await client.query(
      "SELECT current_state FROM rwa.transaction_intents WHERE id=$1 FOR UPDATE",
      [transactionId],
    );
    if (locked.rowCount !== 1) {
      const error = new Error("transaction not found");
      error.code = "UNKNOWN_TRANSACTION";
      throw error;
    }
    const fromState = locked.rows[0].current_state;
    assertTransition(fromState, toState);
    await client.query(
      `UPDATE rwa.transaction_intents SET current_state=$2, row_version=row_version+1, updated_at=clock_timestamp()
       WHERE id=$1`,
      [transactionId, toState],
    );
    await client.query(
      `INSERT INTO rwa.transaction_state_history(transaction_id, from_state, to_state, reason_code, actor_ref)
       VALUES ($1,$2,$3,$4,$5)`,
      [transactionId, fromState, toState, reasonCode, actorRef],
    );
  }

  async appendLedgerBatch(client, { batchId, transactionId = null, sourceType = "TRANSACTION", entries }) {
    assertBalancedEntries(entries);
    const accountIds = [...new Set(entries.map((entry) => entry.accountId))].sort();
    const locked = await client.query(
      "SELECT id FROM rwa.ledger_accounts WHERE id = ANY($1::text[]) ORDER BY id FOR UPDATE",
      [accountIds],
    );
    if (locked.rowCount !== accountIds.length) {
      const error = new Error("one or more ledger accounts do not exist");
      error.code = "UNKNOWN_LEDGER_ACCOUNT";
      throw error;
    }
    await client.query(
      `INSERT INTO rwa.ledger_batches(id,transaction_id,source_type,status,entry_count)
       VALUES ($1,$2,$3,'DRAFT',$4)`,
      [batchId, transactionId, sourceType, entries.length],
    );
    for (const entry of entries) {
      await client.query(
        `INSERT INTO rwa.ledger_entries(batch_id, account_id, asset_code, signed_delta)
         VALUES ($1,$2,$3,$4::numeric)`,
        [batchId, entry.accountId, entry.assetCode, String(entry.signedDelta)],
      );
    }
    await client.query("UPDATE rwa.ledger_batches SET status='POSTED' WHERE id=$1", [batchId]);
  }

  async appendRegisterBatch(client, { batchId, transactionId, assetCode, entries }) {
    assertBalancedEntries(entries);
    const accountIds = [...new Set(entries.map((entry) => entry.accountId))].sort();
    const locked = await client.query(
      "SELECT id FROM rwa.register_accounts WHERE id = ANY($1::text[]) ORDER BY id FOR UPDATE",
      [accountIds],
    );
    if (locked.rowCount !== accountIds.length) {
      const error = new Error("one or more register accounts do not exist");
      error.code = "UNKNOWN_REGISTER_ACCOUNT";
      throw error;
    }
    await client.query(
      `INSERT INTO rwa.register_batches(id,transaction_id,asset_code,status,entry_count)
       VALUES ($1,$2,$3,'DRAFT',$4)`,
      [batchId, transactionId, assetCode, entries.length],
    );
    for (const entry of entries) {
      await client.query(
        `INSERT INTO rwa.register_entries(batch_id,account_id,asset_code,signed_delta)
         VALUES ($1,$2,$3,$4::numeric)`,
        [batchId, entry.accountId, entry.assetCode, String(entry.signedDelta)],
      );
    }
    await client.query("UPDATE rwa.register_batches SET status='POSTED' WHERE id=$1", [batchId]);
  }

  async accountBalance(client, { table = "ledger", accountId }) {
    if (!new Set(["ledger", "register"]).has(table)) throw new Error("unsupported balance table");
    const result = await client.query(
      `SELECT COALESCE(sum(e.signed_delta),0)::text AS balance
       FROM rwa.${table}_entries e
       WHERE e.account_id=$1`,
      [accountId],
    );
    return BigInt(result.rows[0].balance);
  }

  async storeReceipt(client, { transactionId, receipt }) {
    const receiptHash = sha256Canonical(receipt);
    await client.query(
      `INSERT INTO rwa.transaction_receipts(transaction_id,receipt,receipt_hash)
       VALUES ($1,$2::jsonb,$3)`,
      [transactionId, JSON.stringify(receipt), receiptHash],
    );
    return receiptHash;
  }

  async recordAuditEvent(client, event) {
    // Shared tenant lock: writers never block each other, but an audit-chain
    // checkpoint (exclusive) waits for in-flight audit writes to commit, so the
    // sequence boundary it records is final (see audit-checkpoint-service.js).
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))", [auditChainLockKey(event.tenantId)]);
    const lockKey = `${event.tenantId}\u001f${event.aggregateType}\u001f${event.aggregateId}`;
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [lockKey]);
    const previous = await client.query(
      `SELECT event_hash FROM rwa.audit_events
       WHERE tenant_id=$1 AND aggregate_type=$2 AND aggregate_id=$3
       ORDER BY sequence_id DESC LIMIT 1 FOR UPDATE`,
      [event.tenantId, event.aggregateType, event.aggregateId],
    );
    const previousHash = previous.rows[0]?.event_hash ?? null;
    const body = {
      tenantId: event.tenantId,
      eventType: event.eventType,
      aggregateType: event.aggregateType,
      aggregateId: event.aggregateId,
      metadata: event.metadata,
      previousHash,
    };
    const eventHash = sha256Canonical(body);
    await client.query(
      `INSERT INTO rwa.audit_events
       (tenant_id,event_type,aggregate_type,aggregate_id,metadata,previous_hash,event_hash)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
      [event.tenantId, event.eventType, event.aggregateType, event.aggregateId,
        JSON.stringify(event.metadata), previousHash, eventHash],
    );
    return eventHash;
  }

  async proposeExceptionResolution(client, {
    exceptionId, makerRef, decision, replacementTransactionId = null, signature = null,
  }) {
    if (!["RETRY", "CANCEL"].includes(decision)) {
      const error = new Error("maker decision must be RETRY or CANCEL");
      error.code = "INVALID_APPROVAL_DECISION";
      throw error;
    }
    if ((decision === "RETRY" && !replacementTransactionId) || (decision === "CANCEL" && replacementTransactionId)) {
      const error = new Error("maker proposal payload does not match decision");
      error.code = "INVALID_APPROVAL_PAYLOAD";
      throw error;
    }
    const exception = await client.query(
      "SELECT * FROM rwa.exception_cases WHERE id=$1 FOR UPDATE",
      [exceptionId],
    );
    if (exception.rowCount !== 1 || exception.rows[0].status !== "OPEN") {
      const error = new Error("exception is not open");
      error.code = "INVALID_EXCEPTION_STATE";
      throw error;
    }
    const approvalRound = exception.rows[0].approval_round + 1;
    await client.query(
      `INSERT INTO rwa.approval_records
       (exception_id,approval_round,role,actor_ref,decision,proposed_replacement_transaction_id,signature)
       VALUES ($1,$2,'MAKER',$3,$4,$5,$6)`,
      [exceptionId, approvalRound, makerRef, decision, replacementTransactionId, signature],
    );
    const updated = await client.query(
      `UPDATE rwa.exception_cases
       SET status='PENDING_APPROVAL', approval_round=$2, row_version=row_version+1 WHERE id=$1
       RETURNING *`,
      [exceptionId, approvalRound],
    );
    return { exception: updated.rows[0], approvalRound };
  }

  async approveExceptionResolution(client, { exceptionId, checkerRef, decision, signature = null }) {
    if (!["APPROVE", "REJECT"].includes(decision)) {
      const error = new Error("checker decision must be APPROVE or REJECT");
      error.code = "INVALID_APPROVAL_DECISION";
      throw error;
    }
    const exception = await client.query(
      "SELECT * FROM rwa.exception_cases WHERE id=$1 FOR UPDATE",
      [exceptionId],
    );
    const maker = await client.query(
      `SELECT actor_ref,decision,proposed_replacement_transaction_id
       FROM rwa.approval_records
       WHERE exception_id=$1 AND approval_round=$2 AND role='MAKER' FOR UPDATE`,
      [exceptionId, exception.rows[0]?.approval_round ?? 0],
    );
    if (exception.rowCount !== 1 || exception.rows[0].status !== "PENDING_APPROVAL" || maker.rowCount !== 1) {
      const error = new Error("exception has no pending maker proposal");
      error.code = "INVALID_EXCEPTION_STATE";
      throw error;
    }
    if (maker.rows[0].actor_ref === checkerRef) {
      const error = new Error("maker and checker must be different actors");
      error.code = "MAKER_CHECKER_CONFLICT";
      throw error;
    }
    await client.query(
      `INSERT INTO rwa.approval_records(exception_id,approval_round,role,actor_ref,decision,signature)
       VALUES ($1,$2,'CHECKER',$3,$4,$5)`,
      [exceptionId, exception.rows[0].approval_round, checkerRef, decision, signature],
    );
    return {
      exception: exception.rows[0],
      proposalDecision: maker.rows[0].decision,
      replacementTransactionId: maker.rows[0].proposed_replacement_transaction_id,
      checkerDecision: decision,
      makerRef: maker.rows[0].actor_ref,
    };
  }

  async returnExceptionForReview(client, { exceptionId }) {
    const result = await client.query(
      `UPDATE rwa.exception_cases SET status='OPEN', row_version=row_version+1
       WHERE id=$1 AND status='PENDING_APPROVAL' RETURNING *`,
      [exceptionId],
    );
    if (result.rowCount !== 1) {
      const error = new Error("exception is not pending approval");
      error.code = "INVALID_EXCEPTION_STATE";
      throw error;
    }
    return result.rows[0];
  }

  async resolveExceptionCase(client, { exceptionId, status, replacementTransactionId = null }) {
    if (!["RESOLVED_RETRIED", "RESOLVED_CANCELLED"].includes(status)) {
      const error = new Error("invalid resolved exception status");
      error.code = "INVALID_EXCEPTION_STATE";
      throw error;
    }
    const result = await client.query(
      `UPDATE rwa.exception_cases
       SET status=$2, replacement_transaction_id=$3, resolved_at=clock_timestamp(), row_version=row_version+1
       WHERE id=$1 AND status='PENDING_APPROVAL'
       RETURNING *`,
      [exceptionId, status, replacementTransactionId],
    );
    if (result.rowCount !== 1) {
      const error = new Error("exception is not pending approval");
      error.code = "INVALID_EXCEPTION_STATE";
      throw error;
    }
    return result.rows[0];
  }

  async enqueueOutbox(client, { id = randomUUID(), tenantId, topic, aggregateId, payload, availableAt = null }) {
    const payloadHash = sha256Canonical(payload);
    await client.query(
      `INSERT INTO rwa.outbox_events(id,tenant_id,topic,aggregate_id,payload,payload_hash,available_at)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,COALESCE($7,clock_timestamp()))`,
      [id, tenantId, topic, aggregateId, JSON.stringify(payload), payloadHash, availableAt],
    );
    return { id, payloadHash };
  }

  async claimOutboxBatch({ workerId, tenantId = null, limit = 50, leaseMs = 30_000 }) {
    return this.withReadCommittedTransaction(async (client) => {
      const result = await client.query(
        // L4: an event is claimable only when every earlier event for the same
        // tenant/aggregate is PUBLISHED. PENDING, FAILED (backing off), CLAIMED
        // and DEAD predecessors all hold later events back, so at most one event
        // per aggregate is in flight and a dead letter stops its aggregate until
        // the maker/checker replay is executed.
        `WITH candidates AS (
           SELECT e.id FROM rwa.outbox_events e
           WHERE ($4::text IS NULL OR e.tenant_id=$4)
             AND ((e.status IN ('PENDING','FAILED') AND e.available_at <= clock_timestamp())
               OR (e.status='CLAIMED' AND e.lease_expires_at <= clock_timestamp()))
             AND NOT EXISTS (
               SELECT 1 FROM rwa.outbox_events p
               WHERE p.tenant_id=e.tenant_id AND p.aggregate_id=e.aggregate_id
                 AND p.enqueue_sequence < e.enqueue_sequence AND p.status <> 'PUBLISHED'
             )
           ORDER BY e.enqueue_sequence
           FOR UPDATE OF e SKIP LOCKED LIMIT $1
         )
         UPDATE rwa.outbox_events o
         SET status='CLAIMED', claimed_by=$2, claimed_at=clock_timestamp(),
             lease_expires_at=clock_timestamp() + ($3::bigint * interval '1 millisecond'),
             attempts=attempts+1
         FROM candidates c WHERE o.id=c.id
         RETURNING o.*`,
        [limit, workerId, leaseMs, tenantId],
      );
      return result.rows;
    });
  }

  async markOutboxPublished({ id, workerId }) {
    const result = await this.pool.query(
      `UPDATE rwa.outbox_events
       SET status='PUBLISHED', published_at=clock_timestamp(), last_error=NULL,
           claimed_by=NULL, claimed_at=NULL, lease_expires_at=NULL
       WHERE id=$1 AND status='CLAIMED' AND claimed_by=$2
         AND lease_expires_at > clock_timestamp() RETURNING id`,
      [id, workerId],
    );
    if (result.rowCount !== 1) {
      const error = new Error("outbox claim is missing or owned by another worker");
      error.code = "OUTBOX_CLAIM_MISMATCH";
      throw error;
    }
  }

  async markOutboxFailed({ id, workerId, error, dead = false, retryDelayMs = 1_000 }) {
    const status = dead ? "DEAD" : "FAILED";
    const result = await this.pool.query(
      `UPDATE rwa.outbox_events
       SET status=$3, last_error=left($4,2000),
           available_at=CASE WHEN $3='FAILED'
             THEN clock_timestamp() + ($5::bigint * interval '1 millisecond') ELSE available_at END,
           dead_lettered_at=CASE WHEN $3='DEAD' THEN clock_timestamp() ELSE NULL END,
           claimed_by=NULL, claimed_at=NULL, lease_expires_at=NULL
       WHERE id=$1 AND status='CLAIMED' AND claimed_by=$2
         AND lease_expires_at > clock_timestamp() RETURNING id,status`,
      [id, workerId, status, String(error), retryDelayMs],
    );
    if (result.rowCount !== 1) {
      const claimError = new Error("outbox claim is missing, expired or owned by another worker");
      claimError.code = "OUTBOX_CLAIM_MISMATCH";
      throw claimError;
    }
    return result.rows[0];
  }

  async consumeOutboxOnce({ consumerName, event, handler }) {
    return this.withSerializableTransaction(async (client) => {
      const existing = await client.query(
        `SELECT payload_hash,result FROM rwa.inbox_consumptions
         WHERE consumer_name=$1 AND event_id=$2`,
        [consumerName, event.id],
      );
      if (existing.rowCount === 1) {
        if (existing.rows[0].payload_hash !== event.payload_hash) {
          const error = new Error("event id was reused with a different payload");
          error.code = "INBOX_PAYLOAD_CONFLICT";
          throw error;
        }
        return { duplicate: true, result: existing.rows[0].result };
      }
      if (sha256Canonical(event.payload) !== event.payload_hash) {
        const error = new Error("outbox payload hash does not match payload");
        error.code = "OUTBOX_PAYLOAD_TAMPERED";
        throw error;
      }
      const handlerResult = await handler(client, event);
      await client.query(
        `INSERT INTO rwa.inbox_consumptions(consumer_name,event_id,payload_hash,result)
         VALUES ($1,$2,$3,$4::jsonb)`,
        [consumerName, event.id, event.payload_hash, JSON.stringify(handlerResult ?? {})],
      );
      return { duplicate: false, result: handlerResult ?? {} };
    });
  }

  async proposeDeadLetterReplay({ requestId = randomUUID(), eventId, tenantId, makerRef, reason }) {
    return this.withSerializableTransaction(async (client) => {
      const event = await client.query(
        "SELECT status,tenant_id,last_error FROM rwa.outbox_events WHERE id=$1 FOR UPDATE",
        [eventId],
      );
      if (event.rowCount !== 1 || event.rows[0].status !== "DEAD" || event.rows[0].tenant_id !== tenantId) {
        const error = new Error("dead-letter replay requires a matching DEAD event");
        error.code = "INVALID_DEAD_LETTER_STATE";
        throw error;
      }
      await client.query(
        `INSERT INTO rwa.dead_letter_replay_requests
         (id,event_id,tenant_id,maker_ref,reason,dead_error_snapshot)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [requestId, eventId, tenantId, makerRef, reason, event.rows[0].last_error],
      );
      await this.recordAuditEvent(client, {
        tenantId, eventType: "outbox.dead_letter_replay_proposed", aggregateType: "outbox_event",
        aggregateId: eventId, metadata: { requestId, makerRef, reason },
      });
      return { requestId, eventId, state: "PENDING" };
    });
  }

  async decideDeadLetterReplay({ requestId, checkerRef, decision }) {
    if (!["APPROVE", "REJECT"].includes(decision)) {
      const error = new Error("dead-letter replay decision must be APPROVE or REJECT");
      error.code = "INVALID_APPROVAL_DECISION";
      throw error;
    }
    return this.withSerializableTransaction(async (client) => {
      const request = await client.query(
        "SELECT * FROM rwa.dead_letter_replay_requests WHERE id=$1 FOR UPDATE",
        [requestId],
      );
      const row = request.rows[0];
      if (request.rowCount !== 1 || row.status !== "PENDING") {
        const error = new Error("dead-letter replay request is not pending");
        error.code = "INVALID_DEAD_LETTER_STATE";
        throw error;
      }
      if (row.maker_ref === checkerRef) {
        const error = new Error("dead-letter replay maker and checker must differ");
        error.code = "MAKER_CHECKER_CONFLICT";
        throw error;
      }
      if (decision === "REJECT") {
        await client.query(
          `UPDATE rwa.dead_letter_replay_requests
           SET status='REJECTED',checker_ref=$2,checker_decision='REJECT',decided_at=clock_timestamp()
           WHERE id=$1`,
          [requestId, checkerRef],
        );
      } else {
        const event = await client.query(
          "SELECT status FROM rwa.outbox_events WHERE id=$1 FOR UPDATE",
          [row.event_id],
        );
        if (event.rows[0]?.status !== "DEAD") {
          const error = new Error("dead-letter event is no longer replayable");
          error.code = "INVALID_DEAD_LETTER_STATE";
          throw error;
        }
        await client.query(
          `UPDATE rwa.outbox_events
           SET status='PENDING',attempts=0,available_at=clock_timestamp(),claimed_by=NULL,claimed_at=NULL,
               lease_expires_at=NULL,published_at=NULL,dead_lettered_at=NULL,last_error=NULL,replay_count=replay_count+1
           WHERE id=$1`,
          [row.event_id],
        );
        await client.query(
          `UPDATE rwa.dead_letter_replay_requests
           SET status='EXECUTED',checker_ref=$2,checker_decision='APPROVE',decided_at=clock_timestamp(),executed_at=clock_timestamp()
           WHERE id=$1`,
          [requestId, checkerRef],
        );
      }
      await this.recordAuditEvent(client, {
        tenantId: row.tenant_id, eventType: `outbox.dead_letter_replay_${decision.toLowerCase()}`,
        aggregateType: "outbox_event", aggregateId: row.event_id,
        metadata: { requestId, makerRef: row.maker_ref, checkerRef, decision },
      });
      return { requestId, eventId: row.event_id, state: decision === "APPROVE" ? "EXECUTED" : "REJECTED" };
    });
  }
}
