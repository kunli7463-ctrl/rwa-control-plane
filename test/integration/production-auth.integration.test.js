import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ProductionAuthService, authorizePermission } from "../../src/security/production-auth.js";
import { runMigrations, verifyMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("production identity requires MFA, persists only token hashes and rechecks membership", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });
  const migrationState = await verifyMigrations(pool, { migrationsDir });
  assert.equal(migrationState.latest, "021_product_evidence_signature_verification.sql");
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const providerId = `idp-${suffix}`;
  const institutionId = `identity-institution-${suffix}`;
  const principalId = `principal-${suffix}`;
  const tenantId = `tenant-${suffix}`;
  const now = new Date("2026-08-23T12:00:00Z");
  let claims;
  const oidcVerifier = { verify: async () => claims };
  const auth = new ProductionAuthService(store, { oidcVerifier, now: () => now });

  try {
    await pool.query(
      `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem)
       VALUES ($1,'Identity Institution','HK','ACTIVE','test-public-key')`,
      [institutionId],
    );
    await pool.query(
      `INSERT INTO rwa.identity_providers(id,issuer,audience,jwks_uri,status,required_acr)
       VALUES ($1,$2,'rwa-control-plane','https://idp.invalid/jwks','ACTIVE','urn:mfa:high')`,
      [providerId, `https://issuer.invalid/${suffix}`],
    );
    await pool.query(
      `INSERT INTO rwa.principals(id,provider_id,subject,display_name,status)
       VALUES ($1,$2,'oidc-subject','Operations User','ACTIVE')`,
      [principalId, providerId],
    );
    await pool.query(
      `INSERT INTO rwa.institution_memberships
       (principal_id,tenant_id,institution_id,role,status,effective_at)
       VALUES ($1,$2,$3,'operations','ACTIVE',$4)`,
      [principalId, tenantId, institutionId, new Date(now.getTime() - 60_000)],
    );
    claims = {
      providerId, signatureVerified: true, issuer: `https://issuer.invalid/${suffix}`,
      audience: "rwa-control-plane", subject: "oidc-subject", sessionId: `sid-${suffix}`,
      expiresAt: new Date(now.getTime() + 60_000), authTime: new Date(now.getTime() - 1_000),
      mfaTime: new Date(now.getTime() - 1_000), authenticationMethods: ["pwd", "mfa"], acr: "urn:mfa:high",
    };
    const issued = await auth.login({ idToken: "verified-by-adapter", tenantId, role: "operations" });
    assert.equal(issued.cookie.includes("Secure"), true);
    assert.equal(issued.cookie.includes("HttpOnly"), true);
    assert.equal(issued.identity.institutionId, institutionId);
    authorizePermission(issued.identity, "external_incident.approve");
    authorizePermission(issued.identity, "transaction.zk.settle");
    authorizePermission(issued.identity, "transaction.zk.finalize.propose");
    authorizePermission(issued.identity, "transaction.zk.finalize.approve");
    assert.throws(() => authorizePermission(issued.identity, "product.pause"), { code: "AUTHORIZATION_DENIED" });

    const sessionToken = decodeURIComponent(/rwa_session=([^;]+)/.exec(issued.cookie)[1]);
    const stored = await pool.query(
      "SELECT id_hash,csrf_hash,permissions FROM rwa.production_sessions WHERE principal_id=$1",
      [principalId],
    );
    assert.equal(stored.rowCount, 1);
    assert.notEqual(stored.rows[0].id_hash, sessionToken);
    assert.notEqual(stored.rows[0].csrf_hash, issued.csrfToken);
    const session = await auth.authenticate(issued.cookie);
    auth.assertCsrf(session, issued.csrfToken);
    assert.throws(() => auth.assertCsrf(session, "wrong"), { code: "CSRF_REJECTED" });

    await pool.query(
      `UPDATE rwa.institution_memberships SET status='SUSPENDED'
       WHERE principal_id=$1 AND tenant_id=$2 AND role='operations'`,
      [principalId, tenantId],
    );
    await assert.rejects(auth.authenticate(issued.cookie), { code: "SESSION_EXPIRED" });

    await pool.query(
      `UPDATE rwa.institution_memberships SET status='ACTIVE'
       WHERE principal_id=$1 AND tenant_id=$2 AND role='operations'`,
      [principalId, tenantId],
    );
    claims = { ...claims, authenticationMethods: ["pwd"] };
    await assert.rejects(
      auth.login({ idToken: "single-factor", tenantId, role: "operations" }),
      { code: "MFA_REQUIRED" },
    );
    const authEvents = await pool.query(
      `SELECT outcome,reason_code FROM rwa.authentication_events
       WHERE tenant_id=$1 ORDER BY sequence_id`,
      [tenantId],
    );
    assert.deepEqual(authEvents.rows, [
      { outcome: "SUCCESS", reason_code: null },
      { outcome: "DENIED", reason_code: "MFA_REQUIRED" },
    ]);
  } finally {
    await pool.end();
  }
});
