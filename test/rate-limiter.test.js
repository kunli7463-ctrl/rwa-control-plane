import assert from "node:assert/strict";
import test from "node:test";
import { FixedWindowRateLimiter } from "../src/security/rate-limiter.js";

test("fixed-window limiter bounds anonymous requests per client and window", () => {
  let now = 0;
  const limiter = new FixedWindowRateLimiter({ limit: 2, windowMs: 1_000, maxKeys: 2, now: () => now });
  limiter.consume("a");
  limiter.consume("a");
  const limited = (() => { try { limiter.consume("a"); return null; } catch (error) { return error; } })();
  assert.equal(limited.code, "RATE_LIMITED");
  assert.equal(limited.retryAfterSeconds, 1);
  limiter.consume("b");
  assert.throws(() => limiter.consume("c"), { code: "RATE_LIMITED" });
  now = 1_000;
  limiter.consume("a");
  limiter.consume("c");
});
