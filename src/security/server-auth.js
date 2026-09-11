import { randomBytes } from "node:crypto";

const SANDBOX_IDENTITIES = Object.freeze({
  "issuer-console": Object.freeze({ principalId: "issuer-console", tenantId: "sandbox-hk", institutionId: "demo-issuer", role: "issuer", actorRef: null }),
  "distributor-console": Object.freeze({ principalId: "distributor-console", tenantId: "sandbox-hk", institutionId: "demo-broker", role: "distributor", actorRef: null }),
  "investor-a-console": Object.freeze({ principalId: "investor-a-console", tenantId: "sandbox-hk", institutionId: null, role: "investor", actorRef: "investor-a" }),
  "investor-b-console": Object.freeze({ principalId: "investor-b-console", tenantId: "sandbox-hk", institutionId: null, role: "investor", actorRef: "investor-b" }),
  "broker-console": Object.freeze({ principalId: "broker-console", tenantId: "sandbox-hk", institutionId: "demo-broker", role: "broker", actorRef: null }),
  "operations-console": Object.freeze({ principalId: "operations-console", tenantId: "sandbox-hk", institutionId: "demo-admin", role: "operations", actorRef: null }),
  "operations-checker-console": Object.freeze({ principalId: "operations-checker-console", tenantId: "sandbox-hk", institutionId: "demo-admin", role: "operations", actorRef: null }),
  "supervisor-console": Object.freeze({ principalId: "supervisor-console", tenantId: "sandbox-hk", institutionId: "demo-supervisor", role: "supervisor", actorRef: null }),
});

const ACTION_ROLES = new Map([
  ["pause", new Set(["issuer"])],
  ["resume", new Set(["issuer"])],
  ["reset", new Set(["issuer"])],
  ["revoke-b", new Set(["distributor"])],
  ["subscribe", new Set(["investor:investor-a"])],
  ["redeem", new Set(["investor:investor-b"])],
  ["transfer", new Set(["broker"])],
  ["simulate-register-failure", new Set(["operations"])],
  ["propose-exception-retry", new Set(["operations"])],
  ["approve-exception-retry", new Set(["operations"])],
  ["zk-transfer-prepare", new Set(["broker"])],
  ["zk-transfer-authorize", new Set(["broker"])],
  ["zk-transfer-settle", new Set(["broker", "operations"])],
  ["zk-prover-request", new Set(["broker"])],
  ["zk-prover-read", new Set(["broker", "operations"])],
  ["zk-transfer-finality-propose", new Set(["operations"])],
  ["zk-transfer-finality-approve", new Set(["operations"])],
  ["catalog-read", new Set(["issuer", "operations", "supervisor"])],
  ["institution-configure", new Set(["issuer"])],
  ["institution-signing-key-manage", new Set(["issuer"])],
  ["product-configure", new Set(["issuer"])],
  ["institution-review-propose", new Set(["operations"])],
  ["institution-review-approve", new Set(["operations"])],
  ["product-evidence-attach", new Set(["operations"])],
  ["product-activation-propose", new Set(["operations"])],
  ["product-activation-approve", new Set(["operations"])],
  ["catalog-audit-export", new Set(["operations", "supervisor"])],
]);

const ACTION_PERMISSIONS = new Map([
  ["pause", "product.pause"], ["resume", "product.resume"],
  ["revoke-b", "credential.restrict"], ["subscribe", "transaction.subscribe"],
  ["redeem", "transaction.redeem"], ["transfer", "transaction.transfer"],
  ["simulate-register-failure", "exception.propose"],
  ["propose-exception-retry", "exception.propose"],
  ["approve-exception-retry", "exception.approve"],
  ["zk-transfer-prepare", "transaction.zk.prepare"],
  ["zk-transfer-authorize", "transaction.zk.authorize"],
  ["zk-transfer-settle", "transaction.zk.settle"],
  ["zk-prover-request", "transaction.zk.prover.request"],
  ["zk-prover-read", "transaction.zk.prover.read"],
  ["zk-transfer-finality-propose", "transaction.zk.finalize.propose"],
  ["zk-transfer-finality-approve", "transaction.zk.finalize.approve"],
  ["catalog-read", "catalog.read"],
  ["institution-configure", "institution.configure"],
  ["institution-signing-key-manage", "institution.key.manage"],
  ["product-configure", "product.configure"],
  ["institution-review-propose", "institution.review.propose"],
  ["institution-review-approve", "institution.review.approve"],
  ["product-evidence-attach", "product.evidence.attach"],
  ["product-activation-propose", "product.activation.propose"],
  ["product-activation-approve", "product.activation.approve"],
  ["catalog-audit-export", "catalog.audit.read"],
]);

function authError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").flatMap((part) => {
    const index = part.indexOf("=");
    if (index < 1) return [];
    return [[part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())]];
  }));
}

export class SandboxSessionManager {
  constructor({ now = () => new Date(), ttlMs = 30 * 60 * 1000, secureCookies = false } = {}) {
    this.now = now;
    this.ttlMs = ttlMs;
    this.secureCookies = secureCookies;
    this.sessions = new Map();
    this.mode = "SANDBOX_SERVER_SESSION";
  }

  issue(principalId) {
    const identity = SANDBOX_IDENTITIES[principalId];
    if (!identity) throw authError("UNKNOWN_SANDBOX_PRINCIPAL", "sandbox principal is not registered");
    const sessionId = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");
    const expiresAt = new Date(this.now().getTime() + this.ttlMs);
    this.sessions.set(sessionId, { identity, csrfToken, expiresAt });
    return {
      identity: { ...identity },
      csrfToken,
      cookie: this.#cookie(sessionId, Math.floor(this.ttlMs / 1000)),
      expiresAt: expiresAt.toISOString(),
    };
  }

  authenticate(cookieHeader) {
    const sessionId = parseCookies(cookieHeader).rwa_session;
    if (!sessionId) throw authError("AUTHENTICATION_REQUIRED", "server session is required");
    const session = this.sessions.get(sessionId);
    if (!session) throw authError("INVALID_SESSION", "server session is invalid");
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(sessionId);
      throw authError("SESSION_EXPIRED", "server session has expired");
    }
    return { sessionId, identity: { ...session.identity }, csrfToken: session.csrfToken };
  }

  assertCsrf(session, suppliedToken) {
    if (!suppliedToken || suppliedToken !== session.csrfToken) {
      throw authError("CSRF_REJECTED", "state-changing request requires the session CSRF token");
    }
  }

  revoke(sessionId) {
    this.sessions.delete(sessionId);
  }

  #cookie(sessionId, maxAge) {
    return `rwa_session=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${this.secureCookies ? "; Secure" : ""}`;
  }
}

export function authorizeAction(identity, action) {
  if (Array.isArray(identity.permissions)) {
    const permission = ACTION_PERMISSIONS.get(action);
    if (!permission || !identity.permissions.includes(permission)) {
      throw authError("AUTHORIZATION_DENIED", "principal cannot perform this action");
    }
    return;
  }
  const grants = ACTION_ROLES.get(action);
  const roleScope = identity.role === "investor" ? `${identity.role}:${identity.actorRef}` : identity.role;
  if (!grants?.has(roleScope)) throw authError("AUTHORIZATION_DENIED", "principal cannot perform this action");
}

export function assertSandboxAuthMode(mode) {
  if (mode !== "sandbox") {
    throw authError("PRODUCTION_IDENTITY_PROVIDER_REQUIRED", "only sandbox authentication is implemented; configure a verified production identity provider before enabling production mode");
  }
}

export function sandboxIdentity(principalId) {
  const identity = SANDBOX_IDENTITIES[principalId];
  return identity ? { ...identity } : null;
}
