import { createReadStream } from "node:fs";
import { createServer } from "node:http";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { authorizeAction, SandboxSessionManager } from "./security/server-auth.js";
import { ProductionAuthService } from "./security/production-auth.js";
import { RemoteJwksOidcVerifier } from "./security/oidc-verifier.js";
import { DemoRuntime } from "./demo-runtime.js";
import { loadRuntimeConfig } from "./runtime-config.js";
import { WebRequestMetrics } from "./observability/web-metrics.js";
import { loadWebTelemetryConfig, startWebTelemetry } from "./observability/web-telemetry.js";

const publicDir = fileURLToPath(new URL("../public/", import.meta.url));
const config = loadRuntimeConfig();
const telemetryConfig = loadWebTelemetryConfig();
const requestMetrics = new WebRequestMetrics();
const runtime = await DemoRuntime.create(config);
const sessions = config.authMode === "sandbox"
  ? new SandboxSessionManager({ secureCookies: config.cookieSecure })
  : new ProductionAuthService(runtime.store, {
    oidcVerifier: new RemoteJwksOidcVerifier(), secureCookies: true,
  });

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};

function json(response, status, body, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(JSON.stringify(body));
}

async function authenticated(request, { csrf = false } = {}) {
  const session = await sessions.authenticate(request.headers.cookie);
  if (csrf) sessions.assertCsrf(session, request.headers["x-csrf-token"]);
  return session;
}

function errorStatus(error) {
  if (["AUTHENTICATION_REQUIRED", "INVALID_SESSION", "SESSION_EXPIRED"].includes(error.code)) return 401;
  if (["AUTHORIZATION_DENIED", "CSRF_REJECTED"].includes(error.code)) return 403;
  if (error.code?.startsWith("OIDC_") || error.code?.includes("OIDC")
      || ["MFA_REQUIRED", "MFA_ASSURANCE_INSUFFICIENT", "REAUTHENTICATION_REQUIRED"].includes(error.code)) return 401;
  if (error.code === "REQUEST_BODY_TOO_LARGE") return 413;
  if (["IDEMPOTENCY_CONFLICT", "CALLBACK_ID_CONFLICT", "CALLBACK_SEQUENCE_CONFLICT",
    "ZK_TRANSACTION_ALREADY_AUTHORIZED", "NULLIFIER_ALREADY_SPENT", "STALE_ROOT_PUBLICATION",
    "ROOT_FINALIZATION_ALREADY_PROPOSED", "ROOT_PUBLICATION_MISMATCH"].includes(error.code)) return 409;
  if (["PROOF_VERIFIER_UNAVAILABLE", "PROOF_VERIFIER_BUSY", "CONFIDENTIAL_SETTLEMENT_DISABLED",
    "INSTITUTION_CONNECTOR_DISABLED"].includes(error.code)) return 503;
  if (error.code === "TENANT_SCOPE_MISMATCH") return 403;
  if (!/^[A-Z][A-Z0-9_]+$/.test(error.code ?? "")) return 500;
  return 400;
}

function publicError(error, status) {
  if (status >= 500) {
    return {
      ok: false,
      code: status === 503 ? (error.code ?? "SERVICE_UNAVAILABLE") : "INTERNAL_ERROR",
      error: status === 503 ? "service temporarily unavailable" : "internal request failure",
    };
  }
  const body = { ok: false, code: error.code ?? "REQUEST_FAILED", error: error.message };
  if (error.details && typeof error.details === "object" && !Array.isArray(error.details)) {
    body.details = error.details;
  }
  return body;
}

async function bodyOf(request, { maxBytes = 2 * 1024 * 1024 } = {}) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBytes) {
      throw Object.assign(new Error("request body exceeds the configured limit"), { code: "REQUEST_BODY_TOO_LARGE" });
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("request body must be valid JSON"), { code: "INVALID_JSON_BODY" }); }
}

const server = createServer(async (request, response) => {
  requestMetrics.observe(request, response);
  try {
    const url = new URL(request.url, "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/health/live") {
      return json(response, 200, { ok: true, status: "LIVE" });
    }
    if (request.method === "GET" && url.pathname === "/health/ready") {
      try {
        return json(response, 200, { ok: true, status: "READY", ...(await runtime.readiness()) });
      } catch (error) {
        return json(response, 503, { ok: false, status: "NOT_READY", error: "dependency check failed" });
      }
    }
    if (request.method === "POST" && url.pathname === "/api/institution-callbacks") {
      const envelope = await bodyOf(request, { maxBytes: 256 * 1024 });
      if (request.headers["idempotency-key"] !== envelope.callbackId) {
        throw Object.assign(new Error("Idempotency-Key must equal the signed callbackId"), {
          code: "CALLBACK_IDEMPOTENCY_MISMATCH",
        });
      }
      const result = await runtime.receiveInstitutionCallback(envelope);
      return json(response, result.duplicate ? 200 : 202, { ok: true, result });
    }
    if (request.method === "POST" && url.pathname === "/api/sandbox/session") {
      if (config.authMode !== "sandbox") {
        throw Object.assign(new Error("sandbox identity switching is disabled"), { code: "AUTHORIZATION_DENIED" });
      }
      const body = await bodyOf(request);
      try {
        const previous = sessions.authenticate(request.headers.cookie);
        sessions.revoke(previous.sessionId);
      } catch {
        // Replacing a missing or expired Sandbox session is allowed.
      }
      const issued = sessions.issue(body.principalId);
      return json(response, 200, {
        ok: true,
        identity: issued.identity,
        csrfToken: issued.csrfToken,
        expiresAt: issued.expiresAt,
        authMode: sessions.mode,
      }, { "set-cookie": issued.cookie });
    }
    if (request.method === "POST" && url.pathname === "/api/oidc/session") {
      if (config.authMode !== "oidc") {
        throw Object.assign(new Error("OIDC session exchange is disabled in sandbox mode"), { code: "AUTHORIZATION_DENIED" });
      }
      if (request.headers.origin !== config.publicOrigin) {
        throw Object.assign(new Error("OIDC session exchange requires the configured same-site origin"), { code: "CSRF_REJECTED" });
      }
      const body = await bodyOf(request);
      const issued = await sessions.login({ idToken: body.idToken, tenantId: body.tenantId, role: body.role });
      return json(response, 200, {
        ok: true, identity: issued.identity, csrfToken: issued.csrfToken,
        expiresAt: issued.expiresAt, authMode: sessions.mode,
      }, { "set-cookie": issued.cookie });
    }
    if (request.method === "POST" && url.pathname === "/api/session/logout") {
      const session = await authenticated(request, { csrf: true });
      await sessions.revoke(session.sessionId);
      return json(response, 200, { ok: true }, {
        "set-cookie": "rwa_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
      });
    }
    if (request.method === "GET" && url.pathname === "/api/session") {
      const session = await authenticated(request);
      return json(response, 200, { identity: session.identity, authMode: sessions.mode });
    }
    if (request.method === "GET" && url.pathname === "/api/view") {
      const { identity } = await authenticated(request);
      return json(response, 200, await runtime.view(identity, url.searchParams.get("productId") ?? undefined));
    }
    if (request.method === "GET" && url.pathname === "/api/catalog") {
      const { identity } = await authenticated(request);
      authorizeAction(identity, "catalog-read");
      return json(response, 200, { ok: true, catalog: await runtime.productCatalog(identity) });
    }
    if (request.method === "POST" && url.pathname === "/api/catalog/institutions") {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "institution-configure");
      const body = await bodyOf(request, { maxBytes: 64 * 1024 });
      return json(response, 201, { ok: true, institution: await runtime.registerCatalogInstitution(body, identity) });
    }
    if (request.method === "POST" && url.pathname === "/api/catalog/products") {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "product-configure");
      const body = await bodyOf(request, { maxBytes: 64 * 1024 });
      return json(response, 201, { ok: true, product: await runtime.createCatalogProduct(body, identity) });
    }
    if (request.method === "GET" && url.pathname === "/api/catalog/audit-export") {
      const { identity } = await authenticated(request);
      authorizeAction(identity, "catalog-audit-export");
      return json(response, 200, { ok: true, report: await runtime.catalogAuditExport(identity) });
    }
    const institutionReviewProposal = url.pathname.match(/^\/api\/catalog\/institutions\/([^/]+)\/review-proposal$/);
    if (request.method === "POST" && institutionReviewProposal) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "institution-review-propose");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      return json(response, 201, { ok: true, review: await runtime.proposeCatalogInstitutionReview(
        decodeURIComponent(institutionReviewProposal[1]), body, identity,
      ) });
    }
    const institutionReviewDecision = url.pathname.match(/^\/api\/catalog\/institutions\/([^/]+)\/review-decision$/);
    if (request.method === "POST" && institutionReviewDecision) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "institution-review-approve");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      return json(response, 200, { ok: true, review: await runtime.decideCatalogInstitutionReview(
        decodeURIComponent(institutionReviewDecision[1]), body, identity,
      ) });
    }
    const signingKeyRegistration = url.pathname.match(/^\/api\/catalog\/institutions\/([^/]+)\/signing-keys$/);
    if (request.method === "POST" && signingKeyRegistration) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "institution-signing-key-manage");
      const body = await bodyOf(request, { maxBytes: 32 * 1024 });
      return json(response, 201, { ok: true, signingKey: await runtime.registerCatalogInstitutionSigningKey(
        decodeURIComponent(signingKeyRegistration[1]), body, identity,
      ) });
    }
    const signingKeyRevocation = url.pathname.match(/^\/api\/catalog\/institutions\/([^/]+)\/signing-keys\/([^/]+)\/revoke$/);
    if (request.method === "POST" && signingKeyRevocation) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "institution-signing-key-manage");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      return json(response, 200, { ok: true, signingKey: await runtime.revokeCatalogInstitutionSigningKey(
        decodeURIComponent(signingKeyRevocation[1]), decodeURIComponent(signingKeyRevocation[2]), body, identity,
      ) });
    }
    const catalogRole = url.pathname.match(/^\/api\/catalog\/products\/([^/]+)\/roles$/);
    if (request.method === "POST" && catalogRole) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "product-configure");
      const body = await bodyOf(request, { maxBytes: 32 * 1024 });
      const productId = decodeURIComponent(catalogRole[1]);
      return json(response, 200, {
        ok: true, assignment: await runtime.assignCatalogProductRole(productId, body, identity),
      });
    }
    const catalogEvidence = url.pathname.match(/^\/api\/catalog\/products\/([^/]+)\/activation-evidence$/);
    if (request.method === "POST" && catalogEvidence) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "product-evidence-attach");
      const body = await bodyOf(request, { maxBytes: 64 * 1024 });
      return json(response, 201, { ok: true, evidence: await runtime.attachCatalogActivationEvidence(
        decodeURIComponent(catalogEvidence[1]), body, identity,
      ) });
    }
    const activationProposal = url.pathname.match(/^\/api\/catalog\/products\/([^/]+)\/activation-proposal$/);
    if (request.method === "POST" && activationProposal) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "product-activation-propose");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      return json(response, 201, { ok: true, activation: await runtime.proposeCatalogActivation(
        decodeURIComponent(activationProposal[1]), body, identity,
      ) });
    }
    const activationDecision = url.pathname.match(/^\/api\/catalog\/products\/([^/]+)\/activation-decision$/);
    if (request.method === "POST" && activationDecision) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "product-activation-approve");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      return json(response, 200, { ok: true, activation: await runtime.decideCatalogActivation(
        decodeURIComponent(activationDecision[1]), body, identity,
      ) });
    }
    if (request.method === "GET" && url.pathname === "/api/evidence-package") {
      const { identity } = await authenticated(request);
      if (!new Set(["issuer", "broker", "operations", "supervisor"]).has(identity.role)) {
        throw Object.assign(new Error("principal cannot access evidence packages"), { code: "AUTHORIZATION_DENIED" });
      }
      const transactionId = url.searchParams.get("transactionId");
      if (!transactionId) {
        throw Object.assign(new Error("transactionId required"), { code: "MISSING_TRANSACTION_ID" });
      }
      return json(response, 200, await runtime.evidencePackage(transactionId, identity));
    }
    if (request.method === "POST" && url.pathname === "/api/action") {
      const { identity } = await authenticated(request, { csrf: true });
      const body = await bodyOf(request);
      authorizeAction(identity, body.action);
      const result = await runtime.runAction(body.action, identity);
      return json(response, 200, { ok: true, result });
    }
    if (request.method === "POST" && url.pathname === "/api/zk/transfers") {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-prepare");
      const body = await bodyOf(request);
      const result = await runtime.prepareConfidentialTransfer(body, identity);
      return json(response, 201, { ok: true, result });
    }
    const zkAuthorization = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/authorization$/);
    if (request.method === "POST" && zkAuthorization) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-authorize");
      const body = await bodyOf(request);
      const result = await runtime.authorizeConfidentialTransfer(
        decodeURIComponent(zkAuthorization[1]), body.publicInputs, identity,
      );
      return json(response, 200, { ok: true, result });
    }
    const zkSettlement = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/settlement$/);
    if (request.method === "POST" && zkSettlement) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-settle");
      const body = await bodyOf(request);
      const result = await runtime.settleConfidentialTransfer(
        decodeURIComponent(zkSettlement[1]), body, identity,
      );
      return json(response, 200, { ok: true, result });
    }
    const proverJob = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/prover-job$/);
    if (request.method === "POST" && proverJob) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-prover-request");
      const body = await bodyOf(request);
      const result = await runtime.requestProverJob(
        decodeURIComponent(proverJob[1]), body.witnessReference, identity,
      );
      return json(response, 202, { ok: true, result });
    }
    if (request.method === "GET" && proverJob) {
      const { identity } = await authenticated(request);
      authorizeAction(identity, "zk-prover-read");
      const result = await runtime.proverJob(decodeURIComponent(proverJob[1]), identity);
      return json(response, 200, { ok: true, result });
    }
    const zkFinalityProposal = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/finalization-proposal$/);
    if (request.method === "POST" && zkFinalityProposal) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-finality-propose");
      const body = await bodyOf(request);
      const result = await runtime.proposeConfidentialFinality(
        decodeURIComponent(zkFinalityProposal[1]), body, identity,
      );
      return json(response, 201, { ok: true, result });
    }
    const zkFinalityCancellation = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/finalization-cancellation$/);
    if (request.method === "POST" && zkFinalityCancellation) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-finality-cancel");
      const body = await bodyOf(request, { maxBytes: 16 * 1024 });
      const result = await runtime.cancelConfidentialFinality(
        decodeURIComponent(zkFinalityCancellation[1]), body, identity,
      );
      return json(response, 200, { ok: true, result });
    }
    const zkFinalization = url.pathname.match(/^\/api\/zk\/transfers\/([^/]+)\/finalization$/);
    if (request.method === "POST" && zkFinalization) {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "zk-transfer-finality-approve");
      const result = await runtime.approveConfidentialFinality(
        decodeURIComponent(zkFinalization[1]), identity,
      );
      return json(response, 200, { ok: true, result });
    }
    if (request.method === "POST" && url.pathname === "/api/reset") {
      const { identity } = await authenticated(request, { csrf: true });
      authorizeAction(identity, "reset");
      const result = await runtime.runAction("reset", identity);
      return json(response, 200, { ok: true, result });
    }

    if (config.deploymentProfile === "production") {
      return json(response, 404, { ok: false, code: "ROUTE_NOT_FOUND", error: "route not found" });
    }

    const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (relative.includes("..")) return json(response, 400, { error: "invalid path" });
    const path = join(publicDir, relative);
    const stream = createReadStream(path);
    stream.on("open", () => {
      response.writeHead(200, {
        "content-type": MIME[extname(path)] ?? "application/octet-stream",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      });
      stream.pipe(response);
    });
    stream.on("error", () => json(response, 404, { error: "not found" }));
  } catch (error) {
    const status = errorStatus(error);
    json(response, status, publicError(error, status));
  }
});

const port = Number(process.env.PORT ?? 8765);
const host = process.env.HOST ?? "127.0.0.1";
const telemetry = await startWebTelemetry({ config: telemetryConfig, requests: requestMetrics,
  databaseURL: config.storageMode === "postgres" ? config.databaseUrl : null });
server.once("error", async () => { await telemetry?.close(); await runtime.close().catch(() => {}); process.exitCode = 1; });
server.listen(port, host, () => {
  console.log(`RWA ${config.deploymentProfile} runtime (${runtime.storageMode}) listening on http://${host}:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, async () => {
    await telemetry?.close();
    await runtime.close().catch(() => {});
    server.close(() => process.exit(0));
  });
}
