// Fixed-window, per-process limiter for unauthenticated endpoints (M3/L2).
// It bounds how much database and JWKS work an anonymous caller can trigger
// against one instance; the edge proxy/WAF should still rate limit globally.
export class FixedWindowRateLimiter {
  constructor({ limit, windowMs = 60_000, maxKeys = 10_000, now = () => Date.now() }) {
    if (!Number.isInteger(limit) || limit < 1) throw new TypeError("rate limit must be a positive integer");
    if (!Number.isInteger(windowMs) || windowMs < 1_000) throw new TypeError("rate limit window must be at least one second");
    Object.assign(this, { limit, windowMs, maxKeys, now });
    this.windows = new Map();
  }

  consume(key) {
    const current = this.now();
    let entry = this.windows.get(key);
    if (!entry || current - entry.startedAt >= this.windowMs) {
      if (!entry && this.windows.size >= this.maxKeys) this.#evictExpired(current);
      if (!entry && this.windows.size >= this.maxKeys) {
        const error = new Error("too many concurrent clients; retry shortly");
        error.code = "RATE_LIMITED";
        throw error;
      }
      entry = { startedAt: current, count: 0 };
      this.windows.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > this.limit) {
      const error = new Error("request rate limit exceeded; retry later");
      error.code = "RATE_LIMITED";
      error.retryAfterSeconds = Math.max(1, Math.ceil((entry.startedAt + this.windowMs - current) / 1000));
      throw error;
    }
  }

  #evictExpired(current) {
    for (const [key, entry] of this.windows) {
      if (current - entry.startedAt >= this.windowMs) this.windows.delete(key);
    }
  }
}
