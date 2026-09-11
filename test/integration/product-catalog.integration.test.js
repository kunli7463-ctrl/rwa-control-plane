import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { ProductCatalogService } from "../../src/storage/product-catalog-service.js";
import { signProductEvidence } from "../../src/security/product-evidence.js";

const enabled = Boolean(process.env.DATABASE_URL);

function publicKeyPem() {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
}

function evidenceKeyPair() {
  const pair = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privateKey: pair.privateKey,
  };
}

test("product catalog enforces tenant, institution approval and template completeness", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const catalog = new ProductCatalogService(store);
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const tenantA = `tenant-a-${suffix}`;
  const tenantB = `tenant-b-${suffix}`;
  const issuerA = `issuer-a-${suffix}`;
  const providerB = `provider-b-${suffix}`;
  const productId = `product-a-${suffix}`;
  try {
    await catalog.provisionTenant({ id: tenantA, legalName: "Tenant A", homeJurisdiction: "HK", dataRegion: "hk-test" });
    await catalog.provisionTenant({ id: tenantB, legalName: "Tenant B", homeJurisdiction: "AE", dataRegion: "ae-test" });
    await catalog.registerInstitution({
      tenantId: tenantA, actorRef: "tester", institution: {
        id: issuerA, legalName: "Issuer A", jurisdiction: "HK", publicKeyPem: publicKeyPem(),
      },
    });
    await catalog.registerInstitution({
      tenantId: tenantB, actorRef: "tester", institution: {
        id: providerB, legalName: "Provider B", jurisdiction: "AE", publicKeyPem: publicKeyPem(),
      },
    });
    await assert.rejects(catalog.createProduct({
      tenantId: tenantA, actorRef: "tester", product: {
        id: productId, name: "Tenant A Fund", jurisdiction: "HK", issuerId: issuerA,
        currency: "HKD", templateId: "FUND_V1",
      },
    }), { code: "INSTITUTION_NOT_APPROVED" });

    await store.pool.query(
      `UPDATE rwa.tenant_institutions SET onboarding_status='APPROVED'
       WHERE (tenant_id=$1 AND institution_id=$2) OR (tenant_id=$3 AND institution_id=$4)`,
      [tenantA, issuerA, tenantB, providerB],
    );
    const product = await catalog.createProduct({
      tenantId: tenantA, actorRef: "tester", product: {
        id: productId, name: "Tenant A Fund", jurisdiction: "HK", issuerId: issuerA,
        currency: "HKD", templateId: "FUND_V1",
      },
    });
    assert.equal(product.status, "DRAFT");
    assert.equal(product.configurationStatus, "ROLES_PENDING");
    await assert.rejects(catalog.assignRole({
      tenantId: tenantA, actorRef: "tester", productId,
      role: "custodian", institutionId: providerB,
    }), { code: "INSTITUTION_NOT_APPROVED" });
    await assert.rejects(catalog.assignRole({
      tenantId: tenantB, actorRef: "tester", productId,
      role: "custodian", institutionId: providerB,
    }), { code: "UNKNOWN_PRODUCT" });

    const listedA = await catalog.list({ tenantId: tenantA });
    const listedB = await catalog.list({ tenantId: tenantB });
    assert.equal(listedA.products.some((item) => item.id === productId), true);
    assert.equal(listedB.products.some((item) => item.id === productId), false);
    assert.equal(listedA.templates.some((item) => item.id === "SUKUK_V1"), true);
  } finally {
    await store.close();
  }
});

test("catalog governance requires dual approval and complete unexpired activation evidence", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 4 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const catalog = new ProductCatalogService(store);
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const tenantId = `governance-${suffix}`;
  const productId = `bond-${suffix}`;
  const institutions = {
    issuer: `issuer-${suffix}`,
    distributor: `distributor-${suffix}`,
    credential_issuer: `credential-${suffix}`,
    fund_administrator: `administrator-${suffix}`,
    custodian: `custodian-${suffix}`,
    transfer_agent: `registrar-${suffix}`,
    cash_provider: `cash-${suffix}`,
  };
  const evidenceKeys = new Map();
  try {
    await catalog.provisionTenant({ id: tenantId, legalName: "Governance Tenant", homeJurisdiction: "HK", dataRegion: "hk-governance" });
    for (const [role, id] of Object.entries(institutions)) {
      const signingKey = evidenceKeyPair();
      evidenceKeys.set(id, signingKey);
      await catalog.registerInstitution({
        tenantId, actorRef: "issuer-registrar", institution: {
          id, legalName: `Institution ${role}`, jurisdiction: "HK", publicKeyPem: signingKey.publicKeyPem,
        },
      });
      await catalog.proposeInstitutionReview({
        tenantId, institutionId: id, actorRef: "operations-maker",
        input: { decision: "APPROVE", reason: "due diligence package complete" },
      });
      await assert.rejects(catalog.decideInstitutionReview({
        tenantId, institutionId: id, actorRef: "operations-maker",
        input: { decision: "APPROVE", reason: "must not self approve" },
      }), { code: "MAKER_CHECKER_CONFLICT" });
      const approved = await catalog.decideInstitutionReview({
        tenantId, institutionId: id, actorRef: "operations-checker",
        input: { decision: "APPROVE", reason: "independent review complete" },
      });
      assert.equal(approved.state, "APPROVED");
    }

    await catalog.createProduct({
      tenantId, actorRef: "issuer-registrar", product: {
        id: productId, name: "Governed Bond", jurisdiction: "HK", issuerId: institutions.issuer,
        currency: "HKD", templateId: "BOND_V1",
      },
    });
    for (const [role, institutionId] of Object.entries(institutions)) {
      if (role === "issuer") continue;
      await catalog.assignRole({ tenantId, actorRef: "issuer-registrar", productId, role, institutionId });
    }
    await assert.rejects(catalog.proposeActivation({
      tenantId, productId, actorRef: "operations-maker", input: { reason: "activate product" },
    }), { code: "ACTIVATION_EVIDENCE_INCOMPLETE" });

    let listed = await catalog.list({ tenantId });
    const configured = listed.products.find((item) => item.id === productId);
    assert.equal(configured.configurationStatus, "READY_FOR_EVIDENCE");
    const firstRequirement = configured.evidenceRequirements[0];
    const wrongSource = firstRequirement.responsibleRole === "issuer"
      ? institutions.cash_provider : institutions.issuer;
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: {
        id: `bad-evidence-${suffix}`, requirementCode: firstRequirement.code,
        sourceInstitutionId: wrongSource, schemaVersion: "1.0",
        contentHash: createHash("sha256").update("bad-source").digest("hex"),
        envelopeVersion: "rwa.product-activation-evidence.v1",
        signatureAlgorithm: "Ed25519", keyId: "primary-v1",
        signature: Buffer.alloc(64).toString("base64"), issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    }), { code: "EVIDENCE_SOURCE_ROLE_MISMATCH" });

    // The primary signing key is created with the institution's database
    // creation timestamp. Keep the test evidence just after that timestamp;
    // using `now - 60s` accidentally tests the key-validity guard before the
    // deliberately invalid signature can reach cryptographic verification.
    const evidenceIssuedAt = new Date(Date.now() + 1_000).toISOString();
    const invalidFields = {
      tenantId, productId, id: `forged-evidence-${suffix}`,
      requirementCode: firstRequirement.code,
      sourceInstitutionId: institutions[firstRequirement.responsibleRole],
      schemaVersion: "1.0",
      contentHash: createHash("sha256").update("forged-content").digest("hex"),
      issuedAt: evidenceIssuedAt,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      keyId: "primary-v1",
    };
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: {
        ...invalidFields,
        envelopeVersion: "rwa.product-activation-evidence.v1",
        signatureAlgorithm: "Ed25519",
        signature: Buffer.alloc(64).toString("base64"),
      },
    }), { code: "INVALID_EVIDENCE_SIGNATURE" });

    const crossTenantSignature = signProductEvidence(
      { ...invalidFields, tenantId: `other-${tenantId}` },
      evidenceKeys.get(invalidFields.sourceInstitutionId).privateKey,
    );
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: crossTenantSignature,
    }), { code: "INVALID_EVIDENCE_SIGNATURE" });

    const validSignature = signProductEvidence(
      invalidFields,
      evidenceKeys.get(invalidFields.sourceInstitutionId).privateKey,
    );
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: {
        ...validSignature,
        contentHash: createHash("sha256").update("tampered-after-signing").digest("hex"),
      },
    }), { code: "INVALID_EVIDENCE_SIGNATURE" });

    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: {
        ...validSignature, id: `unknown-key-evidence-${suffix}`, keyId: "unknown-v9",
      },
    }), { code: "UNKNOWN_EVIDENCE_SIGNING_KEY" });

    const revokedPair = evidenceKeyPair();
    await catalog.registerInstitutionSigningKey({
      tenantId, actorRef: "issuer-registrar", institutionId: invalidFields.sourceInstitutionId,
      input: {
        keyId: "revoked-v1", algorithm: "Ed25519", publicKeyPem: revokedPair.publicKeyPem,
        validFrom: new Date(Date.now() - 86_400_000), validUntil: new Date(Date.now() + 86_400_000),
      },
    });
    await catalog.revokeInstitutionSigningKey({
      tenantId, actorRef: "issuer-registrar", institutionId: invalidFields.sourceInstitutionId,
      keyId: "revoked-v1", reason: "negative regression test revocation",
    });
    const revokedSignature = signProductEvidence(
      { ...invalidFields, id: `revoked-key-evidence-${suffix}`, keyId: "revoked-v1" },
      revokedPair.privateKey,
    );
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker", input: revokedSignature,
    }), { code: "EVIDENCE_SIGNING_KEY_UNAVAILABLE" });

    const expiredFields = {
      ...invalidFields,
      id: `expired-evidence-${suffix}`,
      issuedAt: new Date(Date.now() - 120_000).toISOString(),
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    };
    await assert.rejects(catalog.attachActivationEvidence({
      tenantId, productId, actorRef: "operations-maker",
      input: signProductEvidence(expiredFields, evidenceKeys.get(expiredFields.sourceInstitutionId).privateKey),
    }), { code: "EVIDENCE_EXPIRED" });

    for (const [index, requirement] of configured.evidenceRequirements.entries()) {
      const fields = {
        tenantId, productId, id: `evidence-${index}-${suffix}`,
        requirementCode: requirement.code,
        sourceInstitutionId: institutions[requirement.responsibleRole], schemaVersion: "1.0",
        contentHash: createHash("sha256").update(`${productId}:${requirement.code}`).digest("hex"),
        issuedAt: evidenceIssuedAt,
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        keyId: "primary-v1",
      };
      await catalog.attachActivationEvidence({
        tenantId, productId, actorRef: "operations-maker",
        input: signProductEvidence(fields, evidenceKeys.get(fields.sourceInstitutionId).privateKey),
      });
    }

    const proposed1 = await catalog.proposeActivation({
      tenantId, productId, actorRef: "operations-maker", input: { reason: "all evidence complete" },
    });
    assert.equal(proposed1.state, "ACTIVATION_PENDING");
    await assert.rejects(catalog.decideActivation({
      tenantId, productId, actorRef: "operations-maker", input: { decision: "APPROVE", reason: "self approval forbidden" },
    }), { code: "MAKER_CHECKER_CONFLICT" });
    const rejected = await catalog.decideActivation({
      tenantId, productId, actorRef: "operations-checker", input: { decision: "REJECT", reason: "return for independent rerun" },
    });
    assert.equal(rejected.state, "READY_FOR_EVIDENCE");
    await catalog.proposeActivation({
      tenantId, productId, actorRef: "operations-maker-2", input: { reason: "rerun complete" },
    });
    const activated = await catalog.decideActivation({
      tenantId, productId, actorRef: "operations-checker-2", input: { decision: "APPROVE", reason: "independent activation approved" },
    });
    assert.equal(activated.state, "ACTIVE");

    listed = await catalog.list({ tenantId });
    const active = listed.products.find((item) => item.id === productId);
    assert.equal(active.status, "ACTIVE");
    assert.equal(active.configurationStatus, "ACTIVE");
    assert.ok(active.evidenceRequirements.every((item) => item.status === "SATISFIED"));
    const transactionCount = await store.pool.query(
      "SELECT count(*)::int AS count FROM rwa.transaction_intents WHERE product_id=$1", [productId],
    );
    assert.equal(transactionCount.rows[0].count, 0);
    const report = await catalog.auditExport({ tenantId });
    assert.match(report.exportHash, /^[0-9a-f]{64}$/);
    assert.ok(report.snapshots.length >= 10);
    assert.ok(report.auditEvents.some((item) => item.eventType === "product.activation_approved"));
  } finally {
    await store.close();
  }
});

test("legacy active products without mandatory evidence are paused during governance upgrade", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 2 });
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(store.pool, { migrationsDir });
  const catalog = new ProductCatalogService(store);
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const tenantId = `legacy-${suffix}`;
  const issuerId = `legacy-issuer-${suffix}`;
  const productId = `legacy-product-${suffix}`;
  try {
    await catalog.provisionTenant({ id: tenantId, legalName: "Legacy Tenant", homeJurisdiction: "HK", dataRegion: "hk-legacy" });
    await catalog.registerInstitution({
      tenantId, actorRef: "legacy-loader", institution: {
        id: issuerId, legalName: "Legacy Issuer", jurisdiction: "HK", publicKeyPem: publicKeyPem(),
      },
    });
    await store.pool.query(
      "UPDATE rwa.tenant_institutions SET onboarding_status='APPROVED' WHERE tenant_id=$1 AND institution_id=$2",
      [tenantId, issuerId],
    );
    await catalog.createProduct({
      tenantId, actorRef: "legacy-loader", product: {
        id: productId, name: "Legacy Evidence-Free Product", jurisdiction: "HK",
        issuerId, currency: "HKD", templateId: "FUND_V1",
      },
    });
    await store.pool.query("UPDATE rwa.products SET status='ACTIVE' WHERE id=$1", [productId]);
    await store.pool.query(
      "UPDATE rwa.product_configurations SET configuration_status='ACTIVE' WHERE product_id=$1",
      [productId],
    );
    const sql = await readFile(path.join(migrationsDir, "020_legacy_catalog_evidence_gate.sql"), "utf8");
    await store.pool.query(sql);
    const state = await store.pool.query(
      `SELECT p.status,c.configuration_status FROM rwa.products p
       JOIN rwa.product_configurations c ON c.product_id=p.id WHERE p.id=$1`,
      [productId],
    );
    assert.deepEqual(state.rows[0], { status: "PAUSED", configuration_status: "SUSPENDED" });
  } finally {
    await store.close();
  }
});
