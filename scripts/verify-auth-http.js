import assert from "node:assert/strict";

const baseUrl = process.env.DEMO_BASE_URL ?? "http://127.0.0.1:8765";

async function jsonRequest(path, { method = "GET", cookie = null, csrfToken = null, body = null } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (csrfToken) headers["x-csrf-token"] = csrfToken;
  if (body) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return {
    status: response.status,
    body: await response.json(),
    cookie: response.headers.get("set-cookie")?.split(";", 1)[0] ?? null,
  };
}

const unauthenticated = await jsonRequest("/api/view");
assert.equal(unauthenticated.status, 401);
assert.equal(unauthenticated.body.code, "AUTHENTICATION_REQUIRED");

const login = await jsonRequest("/api/sandbox/session", {
  method: "POST",
  body: { principalId: "investor-a-console" },
});
assert.equal(login.status, 200);
assert.equal(login.body.identity.role, "investor");
assert.equal(login.body.identity.actorRef, "investor-a");
assert.ok(login.cookie);

const spoofAttempt = await jsonRequest("/api/view?role=supervisor&actorId=investor-b", { cookie: login.cookie });
assert.equal(spoofAttempt.status, 200);
assert.equal(spoofAttempt.body.role, "investor");
assert.equal(spoofAttempt.body.actorId, "investor-a");
assert.equal("auditEvents" in spoofAttempt.body, false);

const missingCsrf = await jsonRequest("/api/action", {
  method: "POST",
  cookie: login.cookie,
  body: { action: "subscribe" },
});
assert.equal(missingCsrf.status, 403);
assert.equal(missingCsrf.body.code, "CSRF_REJECTED");

const crossRoleAction = await jsonRequest("/api/action", {
  method: "POST",
  cookie: login.cookie,
  csrfToken: login.body.csrfToken,
  body: { action: "redeem" },
});
assert.equal(crossRoleAction.status, 403);
assert.equal(crossRoleAction.body.code, "AUTHORIZATION_DENIED");

const allowedAction = await jsonRequest("/api/action", {
  method: "POST",
  cookie: login.cookie,
  csrfToken: login.body.csrfToken,
  body: { action: "subscribe" },
});
assert.equal(allowedAction.status, 200, `subscription rejected: ${allowedAction.body.code ?? "UNKNOWN"}; prepare current synthetic NAV and balances before this acceptance`);
assert.equal(allowedAction.body.result.state, "SETTLED");

console.log("HTTP auth acceptance: unauthenticated, spoofing, CSRF and cross-role checks passed");
