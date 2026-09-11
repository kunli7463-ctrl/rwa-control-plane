import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { InstitutionConnectorClient } from "../sdk/institution-connector.js";
import { validateInstitutionCallbackEnvelope, verifyInstitutionCallbackSignature } from "../src/storage/institution-callback-service.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const payload = {
  subjectType: "TRANSACTION", subjectRef: "tx-1", outcome: "CONFIRMED",
  details: { registerReference: "register-1", assetCode: "UNIT:fund-1", units: "10", registerVersion: 1 },
};

test("connector SDK creates a signed, standalone-conformant institution envelope", () => {
  const client = new InstitutionConnectorClient({ endpoint: "https://rwa.example.test", privateKey });
  const envelope = client.createEnvelope({
    callbackId: "callback-1", tenantId: "tenant-1", institutionId: "ta-1",
    productId: "fund-1", channel: "REGISTER", sequence: 1, payload,
  });
  assert.equal(validateInstitutionCallbackEnvelope(envelope).channel, "REGISTER");
  assert.equal(verifyInstitutionCallbackSignature(envelope, publicKey), true);
});

test("connector SDK submits with callback idempotency and returns the server receipt", async () => {
  const calls = [];
  const client = new InstitutionConnectorClient({
    endpoint: "https://rwa.example.test/base", privateKey,
    fetchImpl: async (url, request) => {
      calls.push({ url, request });
      return new Response(JSON.stringify({ ok: true, result: { callbackId: "callback-1", status: "APPLIED" } }), { status: 202 });
    },
  });
  const envelope = client.createEnvelope({
    callbackId: "callback-1", tenantId: "tenant-1", institutionId: "ta-1",
    productId: "fund-1", channel: "REGISTER", sequence: 1, payload,
  });
  assert.equal((await client.submit(envelope)).status, "APPLIED");
  assert.equal(calls[0].request.headers["idempotency-key"], "callback-1");
  assert.equal(calls[0].url, "https://rwa.example.test/api/institution-callbacks");
});

test("connector SDK refuses insecure non-loopback endpoints and rejected callbacks", async () => {
  assert.throws(() => new InstitutionConnectorClient({ endpoint: "http://rwa.example.test", privateKey }),
    { code: "INSECURE_CONNECTOR_ENDPOINT" });
  const client = new InstitutionConnectorClient({
    endpoint: "https://rwa.example.test", privateKey,
    fetchImpl: async () => new Response(JSON.stringify({ ok: false, code: "CALLBACK_SEQUENCE_CONFLICT", error: "conflict" }), { status: 409 }),
  });
  await assert.rejects(() => client.submit({ callbackId: "callback-1" }), { code: "CALLBACK_SEQUENCE_CONFLICT" });
});
