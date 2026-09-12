import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  callbackPayloadHash,
  createSignedCallback,
  InstitutionCallbackService,
} from "../../src/storage/institution-callback-service.js";
import { runMigrations } from "../../src/storage/migrate.js";
import { PostgresStore } from "../../src/storage/postgres-store.js";
import { EconomicCommitter } from "../../src/security/economic-commitment.js";
import { ExternalIncidentService } from "../../src/storage/external-incident-service.js";

const enabled = Boolean(process.env.DATABASE_URL);

test("signed institutional callbacks reject tampering and apply strictly in stream order", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `callback-tenant-${suffix}`;
  const institutionId = `callback-institution-${suffix}`;
  const productId = `callback-product-${suffix}`;
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const now = new Date();
  const economicCommitter = new EconomicCommitter({ key: Buffer.alloc(32, 7), keyId: "callback-economic-k1" });
  const service = new InstitutionCallbackService(store, { tenantId, now: () => now, economicCommitter });
  const incidentService = new ExternalIncidentService(store, { tenantId });
  const transaction1 = `transaction-1-${suffix}`;
  const transaction2 = `transaction-2-${suffix}`;
  const transaction3 = `transaction-3-${suffix}`;

  function envelope(channel, sequence, payload, overrides = {}) {
    const occurredAt = new Date(now.getTime() - 1_000).toISOString();
    const fields = {
      callbackId: `${channel.toLowerCase()}-${sequence}-${suffix}`,
      tenantId,
      institutionId,
      productId,
      channel,
      sequence,
      eventType: `${channel}.${payload.outcome}`,
      occurredAt,
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      payload,
      payloadHash: callbackPayloadHash(payload),
      ...overrides,
    };
    return createSignedCallback(fields, privateKey);
  }

  try {
    await pool.query(
      `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem)
       VALUES ($1,'Callback Institution','HK','ACTIVE',$2)`,
      [institutionId, publicKey.export({ type: "spki", format: "pem" })],
    );
    await pool.query(
      `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules)
       VALUES ($1,'Callback Product','HK',$2,'HKD','ACTIVE',1,'{}')`,
      [productId, institutionId],
    );
    for (const role of ["transfer_agent", "cash_provider", "custodian"]) {
      await pool.query(
        `INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at)
         VALUES ($1,$2,$3,clock_timestamp())`,
        [productId, role, institutionId],
      );
    }
    for (const transactionId of [transaction1, transaction2, transaction3]) {
      await pool.query(
        `INSERT INTO rwa.transaction_intents
         (id,tenant_id,product_id,idempotency_key,request_hash,transaction_type,current_state,rule_version,
          policy_snapshot_hash,private_payload_ciphertext)
         VALUES ($1,$2,$3,$4,$5,'TRANSFER','SETTLED',1,$6,$7)`,
        [transactionId, tenantId, productId, `idem-${transactionId}`, "a".repeat(64), "b".repeat(64), Buffer.from("encrypted")],
      );
    }
    for (const [transactionId, units, cashAmount] of [
      [transaction1, "10", "100000"], [transaction2, "20", "200000"], [transaction3, "30", "300000"],
    ]) {
      const context = { tenantId, transactionId, productId };
      await pool.query(
        `INSERT INTO rwa.transaction_economic_commitments
         (transaction_id,commitment_version,key_id,asset_code,currency,units_commitment,cash_amount_commitment,fee_amount_commitment)
         VALUES ($1,$2,$3,$4,'HKD',$5,$6,$7)`,
        [transactionId, economicCommitter.version, economicCommitter.keyId, `UNIT:${productId}`,
          economicCommitter.commit({ ...context, field: "units", value: units }),
          economicCommitter.commit({ ...context, field: "cashAmountMinor", value: cashAmount }),
          economicCommitter.commit({ ...context, field: "feeAmountMinor", value: "0" })],
      );
    }

    const crossTenant = envelope("REGISTER", 1, {
      subjectType: "TRANSACTION", subjectRef: transaction1, outcome: "CONFIRMED",
      details: { registerReference: `cross-tenant-${suffix}`, assetCode: `UNIT:${productId}`, units: "10", registerVersion: 1 },
    }, { tenantId: `other-${tenantId}`, callbackId: `cross-tenant-${suffix}` });
    await assert.rejects(service.receive(crossTenant), { code: "CALLBACK_AUTHENTICATION_FAILED", internalReason: "CALLBACK_TENANT_MISMATCH" });

    const second = envelope("REGISTER", 2, {
      subjectType: "TRANSACTION", subjectRef: transaction2, outcome: "CONFIRMED",
      details: { registerReference: `register-2-${suffix}`, assetCode: `UNIT:${productId}`, units: "20", registerVersion: 2 },
    });
    assert.deepEqual(await service.receive(second), {
      callbackId: second.callbackId, duplicate: false, status: "BUFFERED", expectedSequence: 1,
    });
    const first = envelope("REGISTER", 1, {
      subjectType: "TRANSACTION", subjectRef: transaction1, outcome: "CONFIRMED",
      details: { registerReference: `register-1-${suffix}`, assetCode: `UNIT:${productId}`, units: "10", registerVersion: 1 },
    });
    assert.deepEqual(await service.receive(first), {
      callbackId: first.callbackId, duplicate: false, status: "APPLIED", outcome: "CONFIRMED", drained: 1,
    });
    const duplicate = await service.receive(first);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.status, "APPLIED");

    const third = envelope("REGISTER", 3, {
      subjectType: "TRANSACTION", subjectRef: transaction3, outcome: "PERMANENT_FAILURE",
      details: { registerReference: `register-3-${suffix}`, assetCode: `UNIT:${productId}`, units: "30", registerVersion: 3 },
    });
    assert.equal((await service.receive(third)).outcome, "PERMANENT_FAILURE");

    const cash = envelope("CASH", 1, {
      subjectType: "TRANSACTION", subjectRef: transaction1, outcome: "CONFIRMED",
      details: { bankReference: "sandbox-bank-ref", currency: "HKD", amountMinor: "100000", feeMinor: "0" },
    });
    const custody = envelope("CUSTODY", 1, {
      subjectType: "POSITION", subjectRef: `position-${suffix}`, outcome: "CONFIRMED",
      details: { statementId: `statement-${suffix}`, assetCode: `UNIT:${productId}`, balanceUnits: "60", asOf: now.toISOString() },
    });
    assert.equal((await service.receive(cash)).status, "APPLIED");
    assert.equal((await service.receive(custody)).status, "APPLIED");
    const mismatchedCash = envelope("CASH", 2, {
      subjectType: "TRANSACTION", subjectRef: transaction2, outcome: "CONFIRMED",
      details: { bankReference: "wrong-amount-ref", currency: "HKD", amountMinor: "199999", feeMinor: "0" },
    });
    await service.receive(mismatchedCash);
    const mismatch = await pool.query(
      "SELECT reconciliation_status,mismatch_reason FROM rwa.external_callback_confirmations WHERE callback_id=$1",
      [mismatchedCash.callbackId],
    );
    assert.deepEqual(mismatch.rows[0], {
      reconciliation_status: "MISMATCH", mismatch_reason: "CASH_COMMITMENT_MISMATCH",
    });

    const incidents = await pool.query(
      `SELECT id,transaction_id,status,severity,reason_code
       FROM rwa.external_reconciliation_incidents
       WHERE tenant_id=$1 ORDER BY reason_code`,
      [tenantId],
    );
    assert.deepEqual(incidents.rows, [
      {
        id: `external-incident:${mismatchedCash.callbackId}`,
        transaction_id: transaction2,
        status: "OPEN",
        severity: "HIGH",
        reason_code: "CASH_COMMITMENT_MISMATCH",
      },
      {
        id: `external-incident:${third.callbackId}`,
        transaction_id: transaction3,
        status: "OPEN",
        severity: "CRITICAL",
        reason_code: "EXTERNAL_REGISTER_PERMANENT_FAILURE",
      },
    ]);

    const mismatchIncidentId = `external-incident:${mismatchedCash.callbackId}`;
    assert.deepEqual(await incidentService.propose({
      incidentId: mismatchIncidentId,
      makerRef: "incident-maker",
      decision: "REMEDIATE",
      remediationReference: `cash-case-${suffix}`,
    }), { incidentId: mismatchIncidentId, state: "PENDING_APPROVAL", approvalRound: 1 });
    await assert.rejects(incidentService.decide({
      incidentId: mismatchIncidentId, checkerRef: "incident-maker", decision: "APPROVE",
    }), { code: "MAKER_CHECKER_CONFLICT" });
    assert.deepEqual(await incidentService.decide({
      incidentId: mismatchIncidentId, checkerRef: "incident-checker", decision: "APPROVE",
    }), { incidentId: mismatchIncidentId, state: "RESOLVED_REMEDIATED", approvalRound: 1 });

    const failureIncidentId = `external-incident:${third.callbackId}`;
    await incidentService.propose({
      incidentId: failureIncidentId, makerRef: "failure-maker-1", decision: "ACKNOWLEDGE",
    });
    assert.deepEqual(await incidentService.decide({
      incidentId: failureIncidentId, checkerRef: "failure-checker-1", decision: "REJECT",
    }), { incidentId: failureIncidentId, state: "OPEN", approvalRound: 1 });
    assert.deepEqual(await incidentService.propose({
      incidentId: failureIncidentId, makerRef: "failure-maker-2", decision: "ACKNOWLEDGE",
    }), { incidentId: failureIncidentId, state: "PENDING_APPROVAL", approvalRound: 2 });
    assert.deepEqual(await incidentService.decide({
      incidentId: failureIncidentId, checkerRef: "failure-checker-2", decision: "APPROVE",
    }), { incidentId: failureIncidentId, state: "RESOLVED_ACKNOWLEDGED", approvalRound: 2 });

    const resolvedIncidents = await pool.query(
      `SELECT id,status,approval_round,remediation_reference
       FROM rwa.external_reconciliation_incidents
       WHERE tenant_id=$1 ORDER BY id`,
      [tenantId],
    );
    assert.deepEqual(resolvedIncidents.rows, [
      {
        id: failureIncidentId, status: "RESOLVED_ACKNOWLEDGED", approval_round: 2,
        remediation_reference: null,
      },
      {
        id: mismatchIncidentId, status: "RESOLVED_REMEDIATED", approval_round: 1,
        remediation_reference: `cash-case-${suffix}`,
      },
    ].sort((a, b) => a.id.localeCompare(b.id)));
    const approvals = await pool.query(
      `SELECT incident_id,approval_round,role,actor_ref,decision
       FROM rwa.external_incident_approvals
       WHERE incident_id IN ($1,$2) ORDER BY incident_id,approval_round,role DESC`,
      [mismatchIncidentId, failureIncidentId],
    );
    assert.equal(approvals.rowCount, 6);
    const immutableTransactions = await pool.query(
      `SELECT id,current_state FROM rwa.transaction_intents WHERE id IN ($1,$2) ORDER BY id`,
      [transaction2, transaction3],
    );
    assert.ok(immutableTransactions.rows.every((row) => row.current_state === "SETTLED"));

    const tamperedPayload = { ...cash, payload: { ...cash.payload, subjectRef: "attacker-substitution" } };
    await assert.rejects(service.receive(tamperedPayload), { code: "CALLBACK_PAYLOAD_TAMPERED" });
    const tamperedSignedField = { ...custody, eventType: "CUSTODY.FORGED" };
    await assert.rejects(service.receive(tamperedSignedField), { code: "CALLBACK_AUTHENTICATION_FAILED", internalReason: "INVALID_CALLBACK_SIGNATURE" });
    const expiredPayload = {
      subjectType: "TRANSACTION", subjectRef: `expired-${suffix}`, outcome: "REJECTED",
      details: { bankReference: "expired-ref", currency: "HKD", amountMinor: "1", feeMinor: "0" },
    };
    const expired = envelope("CASH", 2, expiredPayload, {
      occurredAt: new Date(now.getTime() - 120_000).toISOString(),
      expiresAt: new Date(now.getTime() - 60_000).toISOString(),
    });
    await assert.rejects(service.receive(expired), { code: "CALLBACK_EXPIRED" });
    const conflicting = envelope("REGISTER", 1, {
      subjectType: "TRANSACTION", subjectRef: `conflict-${suffix}`, outcome: "CONFIRMED",
      details: { registerReference: "conflict", assetCode: `UNIT:${productId}`, units: "1", registerVersion: 1 },
    }, { callbackId: `conflicting-id-${suffix}` });
    await assert.rejects(service.receive(conflicting), { code: "CALLBACK_SEQUENCE_CONFLICT" });

    const state = await pool.query(
      `SELECT
         (SELECT next_sequence::int FROM rwa.callback_stream_positions
          WHERE tenant_id=$1 AND institution_id=$2 AND product_id=$3 AND channel='REGISTER') AS next_sequence,
         (SELECT count(*)::int FROM rwa.callback_applications a JOIN rwa.callback_receipts r USING(callback_id)
          WHERE r.tenant_id=$1 AND r.channel='REGISTER' AND a.status='BUFFERED') AS buffered,
         (SELECT count(*)::int FROM rwa.callback_effects e JOIN rwa.callback_receipts r USING(callback_id)
          WHERE r.tenant_id=$1) AS effects,
         (SELECT count(*)::int FROM rwa.callback_effects e JOIN rwa.callback_receipts r USING(callback_id)
          WHERE r.tenant_id=$1 AND e.outcome='PERMANENT_FAILURE') AS permanent_failures,
         (SELECT count(*)::int FROM rwa.callback_evidence_records e WHERE e.callback_id IN
          (SELECT callback_id FROM rwa.callback_receipts WHERE tenant_id=$1)) AS evidence_count,
         (SELECT external_status FROM rwa.transaction_external_reconciliation WHERE transaction_id=$4) AS transaction1_status`,
      [tenantId, institutionId, productId, transaction1],
    );
    assert.deepEqual(state.rows[0], {
      next_sequence: 4, buffered: 0, effects: 6, permanent_failures: 1,
      evidence_count: 6, transaction1_status: "EXTERNALLY_CONFIRMED",
    });
  } finally {
    await pool.end();
  }
});

test("callback authority follows the governed signing-key registry, including buffered callbacks", { skip: !enabled }, async () => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
  const store = new PostgresStore(pool);
  const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
  await runMigrations(pool, { migrationsDir });
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tenantId = `keys-tenant-${suffix}`;
  const institutionId = `keys-institution-${suffix}`;
  const productId = `keys-product-${suffix}`;
  const primary = generateKeyPairSync("ed25519");
  const rotated = generateKeyPairSync("ed25519");
  const now = new Date();
  const service = new InstitutionCallbackService(store, { tenantId, now: () => now });
  const register = (sequence, { keyId, privateKey = primary.privateKey, institution = institutionId, product = productId } = {}) => {
    const payload = {
      subjectType: "TRANSACTION", subjectRef: `unknown-${sequence}-${suffix}`, outcome: "CONFIRMED",
      details: { registerReference: `ref-${sequence}`, assetCode: `UNIT:${productId}`, units: "1", registerVersion: sequence },
    };
    return createSignedCallback({
      callbackId: `keys-${sequence}-${keyId ?? "default"}-${suffix}`, tenantId, institutionId: institution, productId: product,
      channel: "REGISTER", sequence, eventType: "REGISTER.CONFIRMED",
      occurredAt: new Date(now.getTime() - 1_000).toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      payload, payloadHash: callbackPayloadHash(payload), ...(keyId ? { keyId } : {}),
    }, privateKey);
  };
  try {
    await pool.query(
      `INSERT INTO rwa.institutions(id,legal_name,jurisdiction,status,public_key_pem) VALUES ($1,'Keys','HK','ACTIVE',$2)`,
      [institutionId, primary.publicKey.export({ type: "spki", format: "pem" })],
    );
    await pool.query(
      `INSERT INTO rwa.products(id,name,jurisdiction,issuer_id,currency,status,rule_version,rules) VALUES ($1,'Keys','HK',$2,'HKD','ACTIVE',1,'{}')`,
      [productId, institutionId],
    );
    await pool.query(
      `INSERT INTO rwa.product_role_assignments(product_id,role,institution_id,effective_at) VALUES ($1,'transfer_agent',$2,clock_timestamp())`,
      [productId, institutionId],
    );
    await pool.query(
      `INSERT INTO rwa.institution_signing_keys(institution_id,key_id,algorithm,public_key_pem,status,valid_from)
       VALUES ($1,'rotated-v2','Ed25519',$2,'ACTIVE',clock_timestamp()-interval '1 hour')`,
      [institutionId, rotated.publicKey.export({ type: "spki", format: "pem" })],
    );

    // L2: unknown institution, unassigned product, unknown key and bad signature are indistinguishable.
    const publicShape = (error) => ({ code: error.code, message: error.message, keys: Object.keys(error), details: error.details });
    const rejections = await Promise.all([
      service.receive(register(1, { institution: `ghost-${suffix}` })),
      service.receive(register(1, { product: `other-product-${suffix}` })),
      service.receive(register(1, { keyId: "never-registered" })),
      service.receive(register(1, { privateKey: rotated.privateKey })),
    ].map((attempt) => attempt.then(() => assert.fail("callback must be rejected"), (error) => error)));
    assert.deepEqual(rejections.map((error) => error.internalReason), [
      "UNTRUSTED_CALLBACK_SOURCE", "UNAUTHORIZED_CALLBACK_SOURCE", "CALLBACK_SIGNING_KEY_UNAVAILABLE", "INVALID_CALLBACK_SIGNATURE",
    ]);
    for (const error of rejections) assert.deepEqual(publicShape(error), publicShape(rejections[0]));
    assert.equal(rejections[0].code, "CALLBACK_AUTHENTICATION_FAILED");

    // A compromised primary key pre-positions a future-sequence callback.
    const prePositioned = register(2);
    assert.equal((await service.receive(prePositioned)).status, "BUFFERED");
    await pool.query(
      `UPDATE rwa.institution_signing_keys SET status='REVOKED',revoked_at=clock_timestamp(),valid_until=clock_timestamp()
       WHERE institution_id=$1 AND key_id='primary-v1'`,
      [institutionId],
    );
    await assert.rejects(service.receive(register(3)), { code: "CALLBACK_AUTHENTICATION_FAILED", internalReason: "CALLBACK_SIGNING_KEY_UNAVAILABLE" });
    await assert.rejects(service.receive(register(1, { keyId: "no-such-key" })), { code: "CALLBACK_AUTHENTICATION_FAILED", internalReason: "CALLBACK_SIGNING_KEY_UNAVAILABLE" });
    await assert.rejects(service.receive(register(1, { keyId: "rotated-v2" })), { code: "CALLBACK_AUTHENTICATION_FAILED", internalReason: "INVALID_CALLBACK_SIGNATURE" });

    const applied = await service.receive(register(1, { keyId: "rotated-v2", privateKey: rotated.privateKey }));
    assert.equal(applied.status, "APPLIED");
    assert.equal(applied.drained, 0);
    assert.deepEqual(applied.blockedBuffered, {
      callbackId: prePositioned.callbackId, sequence: 2, reasonCode: "CALLBACK_SIGNING_KEY_UNAVAILABLE",
    });
    const state = await pool.query(
      `SELECT (SELECT next_sequence::int FROM rwa.callback_stream_positions WHERE tenant_id=$1) AS next_sequence,
              (SELECT a.status FROM rwa.callback_applications a WHERE a.callback_id=$2) AS pre_positioned_status,
              (SELECT signing_key_id FROM rwa.callback_receipts WHERE callback_id=$3) AS applied_key,
              (SELECT reason_code FROM rwa.external_reconciliation_incidents WHERE callback_id=$2) AS incident`,
      [tenantId, prePositioned.callbackId, `keys-1-rotated-v2-${suffix}`],
    );
    assert.deepEqual(state.rows[0], {
      next_sequence: 2, pre_positioned_status: "BUFFERED", applied_key: "rotated-v2",
      incident: "BUFFERED_CALLBACK_CALLBACK_SIGNING_KEY_UNAVAILABLE",
    });
  } finally {
    await pool.end();
  }
});
