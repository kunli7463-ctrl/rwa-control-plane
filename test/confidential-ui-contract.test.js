import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [html, app, server, runtime] = await Promise.all([
  readFile(new URL("../public/index.html", import.meta.url), "utf8"),
  readFile(new URL("../public/app.js", import.meta.url), "utf8"),
  readFile(new URL("../src/server.js", import.meta.url), "utf8"),
  readFile(new URL("../src/demo-runtime.js", import.meta.url), "utf8"),
]);

test("confidential settlement UI preserves broker, maker and checker separation", () => {
  assert.match(html, /data-principal="broker-console"/);
  assert.match(html, /data-principal="operations-console"/);
  assert.match(html, /data-principal="operations-checker-console"/);
  assert.match(app, /current\.role === "broker"/);
  assert.match(app, /current\.principalId === "operations-console"/);
  assert.match(app, /current\.principalId === "operations-checker-console"/);
  assert.match(app, /复核人与经办人由服务端和数据库强制分离/);
});

test("confidential settlement UI exposes the five server-controlled phases without claiming legal finality", () => {
  for (const phase of ["交易准备", "公开输入授权", "Groth16 验证", "权威根待确认", "隐私账本终局"]) {
    assert.match(app, new RegExp(phase));
  }
  for (const form of ["prepare", "authorize", "settle", "prover-request", "prover-status", "propose", "approve"]) {
    assert.match(app, new RegExp(`data-zk-form=\\"${form}\\"`));
  }
  assert.match(app, /法定名册仍由外部机构确认/);
  assert.match(app, /data\.runtime\?\.confidentialTransferApi/);
  assert.match(app, /data\.runtime\?\.isolatedProver/);
  assert.match(app, /不得接收原始 witness/);
});

test("every confidential settlement UI mutation maps to a protected HTTP route", () => {
  for (const route of [
    "/api/zk/transfers",
    "/authorization",
    "/settlement",
    "/prover-job",
    "/finalization-proposal",
    "/finalization",
  ]) {
    assert.match(app, new RegExp(route.replaceAll("/", "\\/")));
    assert.match(server, new RegExp(route.replaceAll("/", "\\/")));
  }
  assert.match(app, /x-csrf-token/);
  assert.match(server, /authorizeAction\(identity, "zk-transfer-finality-approve"\)/);
});

test("guided demo prepares synthetic data and walks the existing protected roles", () => {
  assert.match(html, /id="guide-start"/);
  assert.match(html, /id="guide-prepare"/);
  assert.match(html, /id="demo-guide"/);
  assert.match(html, /一键准备演示数据/);
  for (const principal of [
    "issuer-console", "distributor-console", "investor-a-console", "investor-b-console",
    "broker-console", "operations-console", "operations-checker-console", "supervisor-console",
  ]) assert.match(app, new RegExp(principal));
  for (const action of [
    "subscribe", "transfer", "redeem", "simulate-register-failure",
    "propose-exception-retry", "approve-exception-retry", "revoke-b",
  ]) assert.match(app, new RegExp(`action: "${action}"`));
  assert.match(app, /switchPrincipal\(step\.principalId\)/);
  assert.match(app, /data-action="\$\{step\.action\}"/);
  assert.match(app, /fetch\("\/api\/reset"/);
  assert.match(server, /authorizeAction\(identity, "reset"\)/);
});

test("production profile does not serve the synthetic demonstration UI", () => {
  assert.match(server, /config\.deploymentProfile === "production"[\s\S]*ROUTE_NOT_FOUND/);
  assert.match(runtime, /config\.deploymentProfile !== "sandbox"[\s\S]*DEMO_ACTION_FORBIDDEN/);
  assert.match(runtime, /PRODUCTION_NO_SEED/);
});

test("product configuration center uses tenant-scoped protected catalog routes", () => {
  assert.match(html, /id="catalog-open"/);
  assert.match(html, /id="catalog-panel"/);
  assert.match(html, /id="catalog-product-form"/);
  assert.match(html, /DRAFT/);
  for (const route of ["/api/catalog", "/api/catalog/institutions", "/api/catalog/products"]) {
    assert.match(app, new RegExp(route.replaceAll("/", "\\/")));
    assert.match(server, new RegExp(route.replaceAll("/", "\\/")));
  }
  assert.match(server, /authorizeAction\(identity, "catalog-read"\)/);
  assert.match(server, /authorizeAction\(identity, "institution-configure"\)/);
  assert.match(server, /authorizeAction\(identity, "institution-signing-key-manage"\)/);
  assert.match(server, /\/signing-keys/);
  assert.match(server, /authorizeAction\(identity, "product-configure"\)/);
  assert.match(app, /x-csrf-token/);
});

test("catalog governance UI exposes dual-control onboarding, evidence and activation through protected routes", () => {
  assert.match(html, /id="catalog-institutions"/);
  assert.match(html, /id="catalog-audit-export"/);
  for (const formClass of [
    "institution-review-proposal",
    "institution-review-decision",
    "activation-evidence",
    "activation-proposal",
    "activation-decision",
  ]) assert.match(app, new RegExp(formClass));
  for (const route of [
    "/api/catalog/audit-export",
    "/activation-evidence",
    "/activation-proposal",
    "/activation-decision",
  ]) {
    assert.match(app, new RegExp(route.replaceAll("/", "\\/")));
    assert.match(server, new RegExp(route.replaceAll("/", "\\/")));
  }
  for (const suffix of ["review-proposal", "review-decision"]) {
    assert.match(app, new RegExp(suffix));
    assert.match(server, new RegExp(suffix));
  }
  for (const action of [
    "institution-review-propose",
    "institution-review-approve",
    "product-evidence-attach",
    "product-activation-propose",
    "product-activation-approve",
    "catalog-audit-export",
  ]) assert.match(server, new RegExp(`authorizeAction\\(identity, "${action}"\\)`));
  assert.match(app, /current\.principalId === "operations-console"/);
  assert.match(app, /current\.principalId === "operations-checker-console"/);
  assert.match(app, /SHA-256 语义哈希/);
});
