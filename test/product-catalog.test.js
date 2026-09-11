import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  validateInstitutionInput, validateProductInput, validateTenantInput,
} from "../src/storage/product-catalog-service.js";

const template = {
  id: "FUND_V1", status: "ACTIVE",
  defaultRules: {
    allowedInvestorClasses: ["professional"], allowedJurisdictions: ["HK"], maxPriceDeviationBps: 100,
  },
};

test("catalog validation normalizes a bounded tenant and product configuration", () => {
  assert.deepEqual(validateTenantInput({
    id: "tenant-hk-01", legalName: "Example Asset Management", homeJurisdiction: "HK", dataRegion: "hk-prod-1",
  }), {
    id: "tenant-hk-01", legalName: "Example Asset Management", homeJurisdiction: "HK", dataRegion: "hk-prod-1",
  });
  const product = validateProductInput({
    id: "credit-product-01", name: "Private Credit Pilot", jurisdiction: "HK",
    issuerId: "issuer-hk-01", currency: "HKD", rules: { maxPriceDeviationBps: 50 },
  }, template);
  assert.equal(product.templateId, "FUND_V1");
  assert.equal(product.rules.currency, "HKD");
  assert.equal(product.rules.maxPriceDeviationBps, 50);
  assert.deepEqual(product.rules.allowedJurisdictions, ["HK"]);
});

test("catalog rejects identifiers, country codes and unbounded price rules", () => {
  assert.throws(() => validateTenantInput({
    id: "../tenant", legalName: "Bad", homeJurisdiction: "Hong Kong", dataRegion: "hk",
  }), { code: "INVALID_CATALOG_INPUT" });
  assert.throws(() => validateProductInput({
    id: "product-01", name: "Bad Product", jurisdiction: "HK", issuerId: "issuer-01", currency: "HKD",
    rules: { maxPriceDeviationBps: 10_001 },
  }, template), { code: "INVALID_CATALOG_INPUT" });
});

test("institution onboarding accepts only public-key PEM material", () => {
  const publicKeyPem = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
  const institution = validateInstitutionInput({
    id: "issuer-hk-01", legalName: "Example Issuer", jurisdiction: "HK", publicKeyPem,
  });
  assert.equal(institution.id, "issuer-hk-01");
  assert.throws(() => validateInstitutionInput({
    id: "issuer-hk-02", legalName: "Bad Key", jurisdiction: "HK",
    publicKeyPem: `-----BEGIN PRIVATE KEY-----\n${"A".repeat(80)}\n-----END PRIVATE KEY-----`,
  }), { code: "INVALID_INSTITUTION_KEY" });
});

test("evidence verification migration adds key lifecycle and fails legacy evidence closed", async () => {
  const sql = await readFile(new URL("../db/migrations/021_product_evidence_signature_verification.sql", import.meta.url), "utf8");
  for (const boundary of [
    "institution_signing_keys",
    "rwa.product-activation-evidence.v1",
    "verification_status",
    "canonical_payload_hash",
    "signing_key_id",
    "status='MISSING'",
    "configuration_status='SUSPENDED'",
    "status='PAUSED'",
  ]) assert.match(sql, new RegExp(boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("catalog migration preserves approval, draft and tenant isolation boundaries", async () => {
  const sql = await readFile(new URL("../db/migrations/018_product_configuration_catalog.sql", import.meta.url), "utf8");
  for (const required of [
    "REFERENCES rwa.platform_tenants(id)",
    "DUE_DILIGENCE",
    "APPROVED",
    "READY_FOR_EVIDENCE",
    "UNIQUE (tenant_id,product_id)",
    "FUND_V1",
    "PRIVATE_CREDIT_V1",
    "BOND_V1",
    "SUKUK_V1",
    "COMMODITY_V1",
    "institution.configure",
    "product.configure",
  ]) assert.match(sql, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("catalog governance migration enforces dual control, evidence and immutable snapshots", async () => {
  const sql = await readFile(new URL("../db/migrations/019_catalog_governance.sql", import.meta.url), "utf8");
  for (const required of [
    "institution_onboarding_approvals",
    "institution onboarding maker and checker must differ",
    "product_template_evidence_requirements",
    "product_activation_evidence",
    "product_activation_approvals",
    "product activation maker and checker must differ",
    "product_configuration_snapshots",
    "reject_append_only_mutation",
    "product.activation.approve",
    "catalog.audit.read",
  ]) assert.match(sql, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("legacy catalog migration fails closed instead of grandfathering evidence-free active products", async () => {
  const sql = await readFile(new URL("../db/migrations/020_legacy_catalog_evidence_gate.sql", import.meta.url), "utf8");
  for (const boundary of [
    "r.mandatory",
    "r.status<>'SATISFIED'",
    "configuration_status='SUSPENDED'",
    "p.status='ACTIVE'",
    "status='PAUSED'",
  ]) assert.match(sql, new RegExp(boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(sql, /status='ACTIVE'.*configuration_status='ACTIVE'/s);
});
