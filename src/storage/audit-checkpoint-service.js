// L3: global audit-chain checkpoints.
//
// `recordAuditEvent` chains events per aggregate, so a deletion of every event
// of one aggregate cannot be detected from the chain itself. A checkpoint folds
// all audit events, in global sequence order, into one rolling digest:
//
//   digest(n) = sha256({ previousDigest, throughSequenceId, eventCount, events })
//
// Publishing a digest to an external anchor (notary, timestamping service,
// counterparty) is what makes the history externally provable; this module
// supplies the digest, records where it was anchored, and recomputes every
// checkpoint on demand so tampering below an anchored point is detectable.
//
// Sequence ids are assigned before commit, so a lower id can still be in
// flight while a higher one is visible. Audit writes therefore take a SHARED
// tenant advisory lock (writers never block each other) and a checkpoint takes
// the EXCLUSIVE one, so the boundary it reads is final.

import { createHash } from "node:crypto";

const BATCH = 1_000;

export function auditChainLockKey(tenantId) {
  return `rwa.audit-chain\u001f${tenantId}`;
}

function checkpointError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

function digestOf({ previousDigest, throughSequenceId, eventCount, eventHashes }) {
  const hash = createHash("sha256");
  hash.update(`rwa.audit-chain-checkpoint.v1${previousDigest ?? ""}${throughSequenceId}${eventCount}`);
  for (const eventHash of eventHashes) hash.update(`${eventHash}`);
  return hash.digest("hex");
}

export class AuditChainCheckpointService {
  constructor(store, { tenantId, now = () => new Date() }) {
    if (typeof tenantId !== "string" || tenantId.length < 1 || tenantId.length > 200) {
      throw checkpointError("INVALID_TENANT_SCOPE", "audit checkpoints require one bounded tenant scope");
    }
    this.store = store;
    this.tenantId = tenantId;
    this.now = now;
  }

  /** Folds every audit event above the last checkpoint into a new digest. */
  async createCheckpoint({ createdBy }) {
    if (typeof createdBy !== "string" || createdBy.length < 1 || createdBy.length > 200) {
      throw checkpointError("INVALID_CHECKPOINT_ACTOR", "createdBy must be a bounded non-empty string");
    }
    return this.store.withSerializableTransaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [auditChainLockKey(this.tenantId)]);
      const last = await this.#lastCheckpoint(client);
      const from = last ? BigInt(last.through_sequence_id) : 0n;
      const { eventHashes, through } = await this.#eventRange(client, from + 1n, null);
      if (eventHashes.length === 0) {
        throw checkpointError("NO_NEW_AUDIT_EVENTS", "there are no new audit events to checkpoint");
      }
      const eventCount = BigInt(last?.event_count ?? 0) + BigInt(eventHashes.length);
      const digest = digestOf({
        previousDigest: last?.digest ?? null, throughSequenceId: through.toString(), eventCount: eventCount.toString(), eventHashes,
      });
      const checkpointNumber = BigInt(last?.checkpoint_number ?? 0) + 1n;
      await client.query(
        `INSERT INTO rwa.audit_chain_checkpoints
         (tenant_id,checkpoint_number,through_sequence_id,event_count,previous_digest,digest,created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [this.tenantId, checkpointNumber.toString(), through.toString(), eventCount.toString(),
          last?.digest ?? null, digest, createdBy],
      );
      return {
        tenantId: this.tenantId,
        checkpointNumber: Number(checkpointNumber),
        throughSequenceId: through.toString(),
        eventCount: eventCount.toString(),
        previousDigest: last?.digest ?? null,
        digest,
        createdAt: this.now().toISOString(),
      };
    });
  }

  /** Recomputes every checkpoint from the stored events. */
  async verifyCheckpoints() {
    const client = await this.store.pool.connect();
    try {
      const checkpoints = await client.query(
        `SELECT checkpoint_number,through_sequence_id,event_count,previous_digest,digest,external_anchor
         FROM rwa.audit_chain_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_number`,
        [this.tenantId],
      );
      let previousDigest = null;
      let previousThrough = 0n;
      let eventCount = 0n;
      for (const row of checkpoints.rows) {
        const through = BigInt(row.through_sequence_id);
        const { eventHashes } = await this.#eventRange(client, previousThrough + 1n, through);
        eventCount += BigInt(eventHashes.length);
        const mismatch = (reason) => ({
          tenantId: this.tenantId,
          valid: false,
          reason,
          checkpointNumber: Number(row.checkpoint_number),
          throughSequenceId: row.through_sequence_id,
          anchored: Boolean(row.external_anchor),
        });
        if (row.previous_digest !== previousDigest) return mismatch("CHECKPOINT_CHAIN_BROKEN");
        if (BigInt(row.event_count) !== eventCount) return mismatch("EVENT_COUNT_MISMATCH");
        const expected = digestOf({
          previousDigest, throughSequenceId: through.toString(), eventCount: eventCount.toString(), eventHashes,
        });
        if (expected !== row.digest) return mismatch("DIGEST_MISMATCH");
        previousDigest = row.digest;
        previousThrough = through;
      }
      return {
        tenantId: this.tenantId,
        valid: true,
        checkpoints: checkpoints.rowCount,
        eventCount: eventCount.toString(),
        latestDigest: previousDigest,
        latestAnchor: checkpoints.rows[checkpoints.rowCount - 1]?.external_anchor ?? null,
      };
    } finally {
      client.release();
    }
  }

  /** Records where a digest was published; an anchor is written once and never changed. */
  async recordExternalAnchor({ checkpointNumber, anchor }) {
    if (!Number.isSafeInteger(checkpointNumber) || checkpointNumber <= 0) {
      throw checkpointError("INVALID_CHECKPOINT_NUMBER", "checkpointNumber must be a positive integer");
    }
    if (!anchor || typeof anchor !== "object" || Array.isArray(anchor)
        || typeof anchor.service !== "string" || !anchor.service
        || typeof anchor.reference !== "string" || !anchor.reference) {
      throw checkpointError("INVALID_EXTERNAL_ANCHOR", "anchor requires a service and a reference");
    }
    const recorded = { ...anchor, recordedAt: this.now().toISOString() };
    const result = await this.store.pool.query(
      `UPDATE rwa.audit_chain_checkpoints SET external_anchor=$3::jsonb
       WHERE tenant_id=$1 AND checkpoint_number=$2 AND external_anchor IS NULL
       RETURNING digest,through_sequence_id`,
      [this.tenantId, checkpointNumber, JSON.stringify(recorded)],
    );
    if (result.rowCount !== 1) {
      throw checkpointError("CHECKPOINT_ANCHOR_UNAVAILABLE", "checkpoint is unknown or already anchored");
    }
    return { checkpointNumber, digest: result.rows[0].digest, anchor: recorded };
  }

  async #lastCheckpoint(client) {
    const result = await client.query(
      `SELECT checkpoint_number,through_sequence_id,event_count,digest
       FROM rwa.audit_chain_checkpoints WHERE tenant_id=$1
       ORDER BY checkpoint_number DESC LIMIT 1 FOR UPDATE`,
      [this.tenantId],
    );
    return result.rows[0] ?? null;
  }

  /** This tenant's event hashes in global sequence order, `from`..`until` inclusive. */
  async #eventRange(client, from, until) {
    const eventHashes = [];
    let cursor = from;
    let through = from - 1n;
    for (;;) {
      const page = await client.query(
        `SELECT sequence_id,event_hash FROM rwa.audit_events
         WHERE tenant_id=$1 AND sequence_id>=$2 AND ($3::bigint IS NULL OR sequence_id<=$3)
         ORDER BY sequence_id LIMIT ${BATCH}`,
        [this.tenantId, cursor.toString(), until === null ? null : until.toString()],
      );
      for (const row of page.rows) {
        eventHashes.push(row.event_hash);
        through = BigInt(row.sequence_id);
      }
      if (page.rowCount < BATCH) return { eventHashes, through };
      cursor = through + 1n;
    }
  }
}
