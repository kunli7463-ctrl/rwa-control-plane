import assert from "node:assert/strict";
import test from "node:test";
import {
  assertSandboxAuthMode,
  authorizeAction,
  SandboxSessionManager,
  sandboxIdentity,
} from "../src/security/server-auth.js";

test("server session binds role and investor subject from the server directory", () => {
  const manager = new SandboxSessionManager();
  const issued = manager.issue("investor-a-console");
  const authenticated = manager.authenticate(issued.cookie);
  assert.equal(authenticated.identity.role, "investor");
  assert.equal(authenticated.identity.actorRef, "investor-a");
  assert.equal(authenticated.identity.tenantId, "sandbox-hk");
  assert.equal(issued.cookie.includes("HttpOnly"), true);
  assert.equal(issued.cookie.includes("SameSite=Strict"), true);
});

test("expired, missing and unknown sessions fail closed", () => {
  let now = new Date("2026-08-23T12:00:00Z");
  const manager = new SandboxSessionManager({ now: () => now, ttlMs: 1000 });
  const issued = manager.issue("issuer-console");
  assert.throws(() => manager.authenticate(""), { code: "AUTHENTICATION_REQUIRED" });
  assert.throws(() => manager.authenticate("rwa_session=unknown"), { code: "INVALID_SESSION" });
  now = new Date("2026-08-23T12:00:02Z");
  assert.throws(() => manager.authenticate(issued.cookie), { code: "SESSION_EXPIRED" });
});

test("CSRF and action authorization enforce the server identity", () => {
  const manager = new SandboxSessionManager();
  const issued = manager.issue("investor-a-console");
  const session = manager.authenticate(issued.cookie);
  manager.assertCsrf(session, issued.csrfToken);
  assert.throws(() => manager.assertCsrf(session, "wrong"), { code: "CSRF_REJECTED" });
  authorizeAction(session.identity, "subscribe");
  assert.throws(() => authorizeAction(session.identity, "redeem"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(session.identity, "pause"), { code: "AUTHORIZATION_DENIED" });
});

test("production mode cannot silently use the sandbox identity switcher", () => {
  assert.doesNotThrow(() => assertSandboxAuthMode("sandbox"));
  assert.throws(() => assertSandboxAuthMode("oidc"), { code: "PRODUCTION_IDENTITY_PROVIDER_REQUIRED" });
  assert.equal(sandboxIdentity("supervisor-console").role, "supervisor");
  assert.equal(sandboxIdentity("missing"), null);
});

test("production action authorization uses server-issued permissions, not role names", () => {
  const identity = { role: "issuer", permissions: ["external_incident.approve"] };
  assert.throws(() => authorizeAction(identity, "pause"), { code: "AUTHORIZATION_DENIED" });
  const operations = { role: "investor", actorRef: "spoofed", permissions: ["exception.approve"] };
  assert.doesNotThrow(() => authorizeAction(operations, "approve-exception-retry"));
});

test("confidential settlement actions are separately authorized", () => {
  const broker = sandboxIdentity("broker-console");
  const operations = sandboxIdentity("operations-console");
  const investor = sandboxIdentity("investor-a-console");
  assert.doesNotThrow(() => authorizeAction(broker, "zk-transfer-prepare"));
  assert.doesNotThrow(() => authorizeAction(broker, "zk-transfer-authorize"));
  assert.doesNotThrow(() => authorizeAction(broker, "zk-transfer-settle"));
  assert.doesNotThrow(() => authorizeAction(broker, "zk-prover-request"));
  assert.doesNotThrow(() => authorizeAction(broker, "zk-prover-read"));
  assert.doesNotThrow(() => authorizeAction(operations, "zk-prover-read"));
  assert.throws(() => authorizeAction(operations, "zk-prover-request"), { code: "AUTHORIZATION_DENIED" });
  assert.doesNotThrow(() => authorizeAction(operations, "zk-transfer-settle"));
  assert.doesNotThrow(() => authorizeAction(operations, "zk-transfer-finality-propose"));
  assert.doesNotThrow(() => authorizeAction(operations, "zk-transfer-finality-approve"));
  assert.throws(() => authorizeAction(broker, "zk-transfer-finality-approve"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(operations, "zk-transfer-prepare"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(investor, "zk-transfer-settle"), { code: "AUTHORIZATION_DENIED" });
});

test("product configuration separates read access from issuer mutation", () => {
  const issuer = sandboxIdentity("issuer-console");
  const operations = sandboxIdentity("operations-console");
  const supervisor = sandboxIdentity("supervisor-console");
  const broker = sandboxIdentity("broker-console");
  assert.doesNotThrow(() => authorizeAction(issuer, "catalog-read"));
  assert.doesNotThrow(() => authorizeAction(issuer, "institution-configure"));
  assert.doesNotThrow(() => authorizeAction(issuer, "institution-signing-key-manage"));
  assert.doesNotThrow(() => authorizeAction(issuer, "product-configure"));
  assert.doesNotThrow(() => authorizeAction(operations, "catalog-read"));
  assert.doesNotThrow(() => authorizeAction(supervisor, "catalog-read"));
  assert.throws(() => authorizeAction(operations, "product-configure"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(supervisor, "institution-configure"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(operations, "institution-signing-key-manage"), { code: "AUTHORIZATION_DENIED" });
  assert.throws(() => authorizeAction(broker, "catalog-read"), { code: "AUTHORIZATION_DENIED" });
});

test("catalog governance separates issuer, maker, checker and audit permissions", () => {
  const issuer = sandboxIdentity("issuer-console");
  const maker = sandboxIdentity("operations-console");
  const checker = sandboxIdentity("operations-checker-console");
  const supervisor = sandboxIdentity("supervisor-console");
  assert.throws(() => authorizeAction(issuer, "institution-review-propose"), { code: "AUTHORIZATION_DENIED" });
  assert.doesNotThrow(() => authorizeAction(maker, "institution-review-propose"));
  assert.doesNotThrow(() => authorizeAction(checker, "institution-review-approve"));
  assert.doesNotThrow(() => authorizeAction(maker, "product-evidence-attach"));
  assert.doesNotThrow(() => authorizeAction(maker, "product-activation-propose"));
  assert.doesNotThrow(() => authorizeAction(checker, "product-activation-approve"));
  assert.doesNotThrow(() => authorizeAction(supervisor, "catalog-audit-export"));
  assert.throws(() => authorizeAction(supervisor, "product-activation-approve"), { code: "AUTHORIZATION_DENIED" });
});
