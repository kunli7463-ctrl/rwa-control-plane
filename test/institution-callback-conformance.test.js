import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  callbackPayloadHash,
  createSignedCallback,
  validateInstitutionCallbackEnvelope,
  verifyInstitutionCallbackSignature,
} from "../src/storage/institution-callback-service.js";

const now = new Date("2026-08-25T12:00:00.000Z");
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

function registerEnvelope(overrides = {}) {
  const payload = overrides.payload ?? {
    subjectType: "TRANSACTION",
    subjectRef: "transaction-001",
    outcome: "CONFIRMED",
    details: {
      registerReference: "register-001",
      assetCode: "UNIT:hk-fund-001",
      units: "100000000",
      registerVersion: 1,
    },
  };
  return createSignedCallback({
    callbackId: "callback-001",
    tenantId: "tenant-hk-001",
    institutionId: "transfer-agent-001",
    productId: "hk-fund-001",
    channel: "REGISTER",
    sequence: 1,
    eventType: `REGISTER.${payload.outcome}`,
    occurredAt: "2026-08-25T11:59:00.000Z",
    expiresAt: "2026-08-25T12:05:00.000Z",
    payload,
    payloadHash: callbackPayloadHash(payload),
    ...overrides,
  }, privateKey);
}

test("institution callback conformance verifier accepts a valid signed envelope", () => {
  const envelope = registerEnvelope();
  assert.deepEqual(validateInstitutionCallbackEnvelope(envelope, { now }), {
    schema: "rwa.institution-callback.v1",
    channel: "REGISTER",
    requiredRole: "transfer_agent",
  });
  assert.equal(verifyInstitutionCallbackSignature(envelope, publicKey), true);
});

test("institution callback conformance verifier rejects payload and signature tampering", () => {
  const envelope = registerEnvelope();
  assert.throws(() => validateInstitutionCallbackEnvelope({
    ...envelope,
    payload: { ...envelope.payload, subjectRef: "attacker-transaction" },
  }, { now }), { code: "CALLBACK_PAYLOAD_TAMPERED" });
  assert.throws(() => verifyInstitutionCallbackSignature({
    ...envelope,
    eventType: "REGISTER.REJECTED",
  }, publicKey), { code: "INVALID_CALLBACK_SIGNATURE" });
});

test("institution callback conformance verifier enforces channel-specific schemas", () => {
  const invalidPayload = {
    subjectType: "TRANSACTION",
    subjectRef: "transaction-001",
    outcome: "CONFIRMED",
    details: {
      registerReference: "register-001",
      assetCode: "UNIT:hk-fund-001",
      units: "1.5",
      registerVersion: 1,
    },
  };
  const envelope = registerEnvelope({
    payload: invalidPayload,
    payloadHash: callbackPayloadHash(invalidPayload),
  });
  assert.throws(() => validateInstitutionCallbackEnvelope(envelope, { now }), {
    code: "INVALID_CALLBACK_PAYLOAD",
  });
});
