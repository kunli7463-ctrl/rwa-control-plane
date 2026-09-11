import { randomUUID } from "node:crypto";

const MAX_ATTEMPTS = 8;

function jobError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function bounded(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 200) {
    throw jobError("INVALID_PROVER_JOB", `${label} must be a bounded non-empty string`);
  }
  return value;
}

function publicJob(row) {
  return {
    jobId: row.id,
    transactionId: row.transaction_id,
    state: row.state,
    attempts: row.attempts,
    pollCount: row.poll_count,
    nextAttemptAt: row.next_attempt_at?.toISOString?.() ?? row.next_attempt_at,
    proofReceiptId: row.proof_receipt_id,
    lastErrorCode: row.last_error_code,
    requestedAt: row.requested_at?.toISOString?.() ?? row.requested_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
  };
}

export class ProverJobService {
  constructor(store, { proverClient, payloadCipher, zkSettlementGate, tenantId = "sandbox-hk",
    now = () => new Date(), leaseMs = 30_000, logger = console } = {}) {
    if (!proverClient || typeof proverClient.submitJob !== "function" || typeof proverClient.getJob !== "function") {
      throw jobError("PROVER_CLIENT_REQUIRED", "durable prover jobs require an isolated prover client");
    }
    if (!payloadCipher || typeof payloadCipher.encrypt !== "function" || typeof payloadCipher.decrypt !== "function") {
      throw jobError("PAYLOAD_CIPHER_REQUIRED", "durable prover jobs require encrypted witness references");
    }
    if (!zkSettlementGate || typeof zkSettlementGate.accept !== "function") {
      throw jobError("ZK_GATE_REQUIRED", "durable prover jobs require the verified settlement gate");
    }
    this.store = store;
    this.proverClient = proverClient;
    this.payloadCipher = payloadCipher;
    this.zkSettlementGate = zkSettlementGate;
    this.tenantId = tenantId;
    this.now = now;
    this.leaseMs = leaseMs;
    this.logger = logger;
  }

  async request({ transactionId, tenantId = this.tenantId, witnessReference, requestedBy, actorInstitutionId }) {
    bounded(transactionId, "transactionId");
    bounded(requestedBy, "requestedBy");
    if (tenantId !== this.tenantId) throw jobError("TENANT_SCOPE_MISMATCH", "prover job is outside this runtime tenant");
    if (typeof witnessReference !== "string" || witnessReference.length > 500
        || !/^(vault|hsm|kmsref):\/\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(witnessReference)) {
      throw jobError("INVALID_WITNESS_REFERENCE", "an opaque bounded witness reference is required");
    }
    return this.store.withSerializableTransaction(async (client) => {
      const context = await client.query(
        `SELECT t.product_id,t.current_state,t.originating_institution_id,a.status,a.circuit_id,a.circuit_version,a.public_inputs_hash
         FROM rwa.transaction_intents t
         JOIN rwa.zk_transaction_authorizations a ON a.transaction_id=t.id AND a.tenant_id=t.tenant_id
         WHERE t.id=$1 AND t.tenant_id=$2 FOR UPDATE OF t,a`,
        [transactionId, tenantId],
      );
      if (context.rowCount !== 1) throw jobError("ZK_TRANSACTION_NOT_AUTHORIZED", "transaction has no immutable ZK authorization");
      const row = context.rows[0];
      if (actorInstitutionId !== undefined && (!actorInstitutionId || row.originating_institution_id !== actorInstitutionId)) {
        throw jobError("ZK_TRANSACTION_NOT_AUTHORIZED", "transaction is unavailable to this institution");
      }
      if (row.current_state !== "PROOF_PENDING" || row.status !== "PENDING") {
        throw jobError("INVALID_ZK_TRANSACTION_STATE", "transaction is not awaiting proof generation");
      }
      const existing = await client.query(
        "SELECT * FROM rwa.prover_jobs WHERE transaction_id=$1 AND tenant_id=$2",
        [transactionId, tenantId],
      );
      if (existing.rowCount === 1) return { ...publicJob(existing.rows[0]), created: false };
      const jobId = `prover:${transactionId}:${randomUUID()}`;
      const encrypted = await this.payloadCipher.encrypt({ witnessReference }, {
        tenantId, transactionId, productId: row.product_id, transactionType: "PROVER_JOB",
      });
      const inserted = await client.query(
        `INSERT INTO rwa.prover_jobs
         (id,transaction_id,tenant_id,product_id,circuit_id,circuit_version,authorization_hash,
          witness_reference_ciphertext,state,requested_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'QUEUED',$9) RETURNING *`,
        [jobId, transactionId, tenantId, row.product_id, row.circuit_id, row.circuit_version,
          row.public_inputs_hash, encrypted, requestedBy],
      );
      const metadata = { productId: row.product_id, transactionId, jobId, state: "QUEUED" };
      await this.store.recordAuditEvent(client, {
        tenantId, eventType: "zk.prover_job.queued", aggregateType: "transaction", aggregateId: transactionId, metadata,
      });
      await this.store.enqueueOutbox(client, {
        tenantId, topic: "rwa.zk.prover_job.queued", aggregateId: transactionId, payload: metadata,
      });
      return { ...publicJob(inserted.rows[0]), created: true };
    });
  }

  async get({ transactionId, tenantId = this.tenantId, actorInstitutionId }) {
    bounded(transactionId, "transactionId");
    const result = await this.store.pool.query(
      `SELECT j.* FROM rwa.prover_jobs j JOIN rwa.transaction_intents t ON t.id=j.transaction_id
       WHERE j.transaction_id=$1 AND j.tenant_id=$2
         AND ($3::text IS NULL OR t.originating_institution_id=$3)`,
      [transactionId, tenantId, actorInstitutionId === undefined ? null : (actorInstitutionId || "\u0000")],
    );
    if (result.rowCount !== 1) throw jobError("UNKNOWN_PROVER_JOB", "prover job was not found");
    return publicJob(result.rows[0]);
  }

  async runOnce({ workerId = `prover-worker:${randomUUID()}` } = {}) {
    bounded(workerId, "workerId");
    const claimed = await this.store.withReadCommittedTransaction(async (client) => {
      // A worker that crashed or stalled past its lease leaves the job in
      // SUBMITTING/VERIFYING. Count that as one failed attempt and make the
      // job claimable again; the remote request id is the job id, so a
      // resubmission is idempotent at the prover service.
      await client.query(
        `UPDATE rwa.prover_jobs
         SET state=CASE WHEN attempts+1>=$2 THEN 'FAILED' ELSE 'RETRYABLE' END,
             attempts=attempts+1,lease_owner=NULL,lease_expires_at=NULL,
             last_error_code='PROVER_LEASE_EXPIRED',next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE tenant_id=$1 AND state IN ('SUBMITTING','VERIFYING')
           AND lease_expires_at<=clock_timestamp()`,
        [this.tenantId, MAX_ATTEMPTS],
      );
      const result = await client.query(
        `SELECT * FROM rwa.prover_jobs
         WHERE tenant_id=$1 AND state IN ('QUEUED','REMOTE_PENDING','RETRYABLE')
           AND next_attempt_at<=clock_timestamp()
           AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())
         ORDER BY next_attempt_at,requested_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`,
        [this.tenantId],
      );
      if (result.rowCount === 0) return null;
      const row = result.rows[0];
      const nextState = row.external_job_id ? "VERIFYING" : "SUBMITTING";
      const updated = await client.query(
        `UPDATE rwa.prover_jobs SET state=$2,lease_owner=$3,
           poll_count=poll_count+CASE WHEN external_job_id IS NULL THEN 0 ELSE 1 END,
           lease_expires_at=clock_timestamp()+($4::int * interval '1 millisecond'),updated_at=clock_timestamp()
         WHERE id=$1 RETURNING *`,
        [row.id, nextState, workerId, this.leaseMs],
      );
      return updated.rows[0];
    });
    if (!claimed) return null;
    try {
      if (!claimed.external_job_id) return await this.#submit(claimed, workerId);
      return await this.#poll(claimed, workerId);
    } catch (error) {
      this.logger.error?.("isolated prover job attempt failed", {
        jobId: claimed.id,
        transactionId: claimed.transaction_id,
        state: claimed.state,
        attempts: claimed.attempts,
        errorCode: error?.code ?? "PROVER_SERVICE_FAILURE",
        errorMessage: error?.message ?? "unknown prover failure",
      });
      return this.#retry(claimed, workerId, error);
    }
  }

  async #submit(job, workerId) {
    const decrypted = await this.payloadCipher.decrypt(job.witness_reference_ciphertext, {
      tenantId: job.tenant_id, transactionId: job.transaction_id,
      productId: job.product_id, transactionType: "PROVER_JOB",
    });
    const remote = await this.proverClient.submitJob({
      requestId: job.id, transactionId: job.transaction_id, circuitId: job.circuit_id,
      circuitVersion: job.circuit_version, authorizationHash: job.authorization_hash,
      witnessReference: decrypted.witnessReference,
    });
    const result = await this.store.pool.query(
      `UPDATE rwa.prover_jobs SET state='REMOTE_PENDING',external_job_id=$3,lease_owner=NULL,
         lease_expires_at=NULL,next_attempt_at=clock_timestamp()+interval '1 second',last_error_code=NULL,
         updated_at=clock_timestamp() WHERE id=$1 AND lease_owner=$2 AND state='SUBMITTING' RETURNING *`,
      [job.id, workerId, remote.jobId],
    );
    if (result.rowCount !== 1) throw jobError("PROVER_JOB_LEASE_LOST", "prover job lease was lost after submission");
    return publicJob(result.rows[0]);
  }

  async #poll(job, workerId) {
    const remote = await this.proverClient.getJob(job.external_job_id);
    if (new Set(["QUEUED", "RUNNING"]).has(remote.state)) {
      const pending = await this.store.pool.query(
        `UPDATE rwa.prover_jobs SET state='REMOTE_PENDING',lease_owner=NULL,lease_expires_at=NULL,
           next_attempt_at=clock_timestamp()+(LEAST(30,2*power(2,LEAST(poll_count/5,4)))::int * interval '1 second'),
           updated_at=clock_timestamp()
         WHERE id=$1 AND lease_owner=$2 AND state='VERIFYING' RETURNING *`,
        [job.id, workerId],
      );
      if (pending.rowCount !== 1) throw jobError("PROVER_JOB_LEASE_LOST", "prover job lease was lost while polling");
      return publicJob(pending.rows[0]);
    }
    if (new Set(["FAILED", "CANCELLED"]).has(remote.state)) {
      const failed = await this.store.pool.query(
        `UPDATE rwa.prover_jobs SET state='FAILED',lease_owner=NULL,lease_expires_at=NULL,last_error_code=$3,
           updated_at=clock_timestamp() WHERE id=$1 AND lease_owner=$2 AND state='VERIFYING' RETURNING *`,
        [job.id, workerId, remote.errorCode ?? "PROVER_JOB_FAILED"],
      );
      if (failed.rowCount !== 1) throw jobError("PROVER_JOB_LEASE_LOST", "prover job lease was lost while recording failure");
      return publicJob(failed.rows[0]);
    }
    let accepted;
    try {
      accepted = await this.zkSettlementGate.accept({
        transactionId: job.transaction_id, tenantId: job.tenant_id,
        proof: remote.proof, publicSignals: remote.publicSignals,
      });
    } catch (error) {
      if (error.code !== "ZK_TRANSACTION_NOT_AUTHORIZED") throw error;
      const receipt = await this.store.pool.query(
        "SELECT id FROM rwa.zk_proof_receipts WHERE transaction_id=$1 AND tenant_id=$2",
        [job.transaction_id, job.tenant_id],
      );
      if (receipt.rowCount !== 1) throw error;
      accepted = { receiptId: receipt.rows[0].id };
    }
    const receiptId = accepted.receiptId ?? accepted.proofReceiptId;
    if (typeof receiptId !== "string" || receiptId.length === 0) {
      throw jobError("INVALID_ZK_GATE_RECEIPT", "verified ZK gate did not return a proof receipt identity");
    }
    const verified = await this.store.pool.query(
      `UPDATE rwa.prover_jobs SET state='VERIFIED',proof_receipt_id=$3,lease_owner=NULL,
         lease_expires_at=NULL,last_error_code=NULL,updated_at=clock_timestamp()
       WHERE id=$1 AND lease_owner=$2 AND state='VERIFYING' RETURNING *`,
      [job.id, workerId, receiptId],
    );
    if (verified.rowCount !== 1) throw jobError("PROVER_JOB_LEASE_LOST", "prover job lease was lost after verification");
    return publicJob(verified.rows[0]);
  }

  async #retry(job, workerId, error) {
    const failedAttempts = job.attempts + 1;
    const terminal = failedAttempts >= MAX_ATTEMPTS;
    const delaySeconds = Math.min(60, 2 ** Math.min(failedAttempts, 6));
    const result = await this.store.pool.query(
      `UPDATE rwa.prover_jobs SET state=$3,attempts=attempts+1,lease_owner=NULL,lease_expires_at=NULL,last_error_code=$4,
         next_attempt_at=clock_timestamp()+($5::int * interval '1 second'),updated_at=clock_timestamp()
       WHERE id=$1 AND lease_owner=$2 AND state IN ('SUBMITTING','VERIFYING') RETURNING *`,
      [job.id, workerId, terminal ? "FAILED" : "RETRYABLE",
        /^[A-Z][A-Z0-9_]{0,79}$/.test(error.code ?? "") ? error.code : "PROVER_SERVICE_FAILURE", delaySeconds],
    );
    if (result.rowCount !== 1) throw error;
    return publicJob(result.rows[0]);
  }
}
