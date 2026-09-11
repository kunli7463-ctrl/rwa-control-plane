function assertPositiveInteger(value, name) {
  if (!Number.isInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive integer`);
}

export function retryDelayMs(attempt, { baseDelayMs = 1_000, maxDelayMs = 300_000 } = {}) {
  assertPositiveInteger(attempt, "attempt");
  assertPositiveInteger(baseDelayMs, "baseDelayMs");
  assertPositiveInteger(maxDelayMs, "maxDelayMs");
  return Math.min(maxDelayMs, baseDelayMs * (2 ** Math.min(attempt - 1, 30)));
}

export class OutboxDispatcher {
  constructor({ store, workerId, tenantId = null, publish, leaseMs = 30_000, maxAttempts = 8, baseDelayMs = 1_000, maxDelayMs = 300_000 }) {
    if (!store || typeof store.claimOutboxBatch !== "function") throw new TypeError("store is required");
    if (!workerId) throw new TypeError("workerId is required");
    if (typeof publish !== "function") throw new TypeError("publish must be a function");
    for (const [value, name] of [[leaseMs, "leaseMs"], [maxAttempts, "maxAttempts"], [baseDelayMs, "baseDelayMs"], [maxDelayMs, "maxDelayMs"]]) {
      assertPositiveInteger(value, name);
    }
    this.store = store;
    this.workerId = workerId;
    this.tenantId = tenantId;
    this.publish = publish;
    this.leaseMs = leaseMs;
    this.maxAttempts = maxAttempts;
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
  }

  async dispatchBatch({ limit = 50 } = {}) {
    assertPositiveInteger(limit, "limit");
    const events = await this.store.claimOutboxBatch({
      workerId: this.workerId, tenantId: this.tenantId, limit, leaseMs: this.leaseMs,
    });
    const result = { claimed: events.length, published: 0, failed: 0, dead: 0 };
    for (const event of events) {
      try {
        await this.publish(event);
        await this.store.markOutboxPublished({ id: event.id, workerId: this.workerId });
        result.published += 1;
      } catch (error) {
        const dead = event.attempts >= this.maxAttempts;
        await this.store.markOutboxFailed({
          id: event.id,
          workerId: this.workerId,
          error: error instanceof Error ? error.message : String(error),
          dead,
          retryDelayMs: retryDelayMs(event.attempts, { baseDelayMs: this.baseDelayMs, maxDelayMs: this.maxDelayMs }),
        });
        result[dead ? "dead" : "failed"] += 1;
      }
    }
    return result;
  }
}

export class SimulatedRegisterCallbackConsumer {
  constructor({ store, consumerName = "sandbox-register-callback" }) {
    this.store = store;
    this.consumerName = consumerName;
  }

  async consume(event) {
    return this.store.consumeOutboxOnce({
      consumerName: this.consumerName,
      event,
      handler: async (client) => {
        const transactionId = event.payload.transactionId ?? event.aggregate_id;
        await client.query(
          `INSERT INTO rwa.register_callback_events(event_id,transaction_id,callback_type,payload_hash)
           VALUES ($1,$2,$3,$4)`,
          [event.id, transactionId, event.topic, event.payload_hash],
        );
        return { transactionId, callbackType: event.topic };
      },
    });
  }
}
