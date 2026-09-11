import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ELIGIBLE_RULES_JSON } from "../helpers/confidential-parties.js";
import { RedactedPayloadCipher } from "../../src/security/envelope-crypto.js";
import { ConfidentialTransferService } from "../../src/storage/confidential-transfer-service.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("only the product distributor can register note owner keys for eligible investors", { skip: !enabled }, async () => {
  const store = await PostgresStore.connect({ connectionString: process.env.DATABASE_URL, max: 2 });
  await runMigrations(store.pool, { migrationsDir: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations") });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `owner-keys-${suffix}`;
  const productId = `owner-keys-product-${suffix}`;
  const issuerId = `owner-keys-issuer-${suffix}`;
  const distributorId = `owner-keys-distributor-${suffix}`;
  const query = (sql, values) => store.pool.query(sql, values);
  const service = new ConfidentialTransferService(store, {
    payloadCipher: new RedactedPayloadCipher(), circuitId: "unused", circuitVersion: "unused", tenantId,
  });
  try {
    for (const id of [issuerId, distributorId]) {
      await query("INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'I','HK','ACTIVE','test')", [id]);
    }
    await query("INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'K','HK',$2,'HKD','ACTIVE',1,$3::jsonb)",
      [productId, issuerId, ELIGIBLE_RULES_JSON]);
    await query(`INSERT INTO rwa.ledger_accounts(id,tenant_id,product_id,owner_ref,asset_code,account_type)
      VALUES ($1,$2,$3,'owner',$4,'INVESTOR')`, [`ledger-${suffix}`, tenantId, productId, `UNIT:${productId}`]);
    await query(`INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at)
      VALUES ($1,'distributor',$2,clock_timestamp())`, [productId, distributorId]);
    for (const [credentialId, jurisdiction] of [["eligible", "HK"], ["foreign", "US"]]) {
      await query(`INSERT INTO rwa.credentials
        (id,product_id,issuer_id,subject_ref,investor_class,jurisdiction,max_units,valid_from,valid_until,status,signed_payload,signature)
        VALUES ($1,$2,$3,$4,'professional',$5,100,clock_timestamp()-interval '1 day',clock_timestamp()+interval '1 day','ACTIVE','{}'::jsonb,'sig')`,
      [`${credentialId}-${suffix}`, productId, issuerId, `investor-${credentialId}-${suffix}`, jurisdiction]);
    }
    const registration = {
      tenantId, productId, subjectRef: `investor-eligible-${suffix}`, credentialId: `eligible-${suffix}`,
      ownerPublicKey: "777", registeredBy: "distributor-user", actorInstitutionId: distributorId,
    };
    await assert.rejects(service.registerOwnerKey({ ...registration, actorInstitutionId: issuerId }), { code: "AUTHORIZATION_DENIED" });
    await assert.rejects(service.registerOwnerKey({ ...registration, subjectRef: `investor-foreign-${suffix}`,
      credentialId: `foreign-${suffix}` }), { code: "CONFIDENTIAL_PARTY_INELIGIBLE" });
    await assert.rejects(service.registerOwnerKey({ ...registration, ownerPublicKey: "0" }), { code: "INVALID_NOTE_OWNER_KEY" });
    assert.equal((await service.registerOwnerKey(registration)).status, "ACTIVE");
    await assert.rejects(service.registerOwnerKey(registration), { code: "NOTE_OWNER_KEY_ALREADY_REGISTERED" });
    const revocation = { tenantId, productId, ownerPublicKey: "777", revokedBy: "distributor-user", reason: "device lost" };
    await assert.rejects(service.revokeOwnerKey({ ...revocation, tenantId: "other" }), { code: "TENANT_SCOPE_MISMATCH" });
    assert.equal((await service.revokeOwnerKey(revocation)).status, "REVOKED");
    await assert.rejects(service.revokeOwnerKey(revocation), { code: "NOTE_OWNER_KEY_NOT_ACTIVE" });
    await assert.rejects(query("DELETE FROM rwa.confidential_note_owner_keys WHERE product_id=$1", [productId]), { code: "55000" });
  } finally {
    await store.close();
  }
});
