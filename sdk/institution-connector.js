import { callbackPayloadHash, createSignedCallback } from "../src/storage/institution-callback-service.js";

function connectorError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function bounded(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 200) {
    throw connectorError("INVALID_CONNECTOR_FIELD", `${label} must be a bounded non-empty string`);
  }
  return value;
}

export class InstitutionConnectorClient {
  constructor({ endpoint, privateKey, fetchImpl = globalThis.fetch, timeoutMs = 10_000,
    allowLoopbackHttp = false } = {}) {
    let url;
    try { url = new URL(endpoint); }
    catch { throw connectorError("INVALID_CONNECTOR_ENDPOINT", "connector endpoint must be an absolute URL"); }
    const loopback = new Set(["127.0.0.1", "localhost", "::1"]).has(url.hostname);
    if (url.protocol !== "https:" && !(allowLoopbackHttp && loopback && url.protocol === "http:")) {
      throw connectorError("INSECURE_CONNECTOR_ENDPOINT", "institution callback endpoint must use HTTPS");
    }
    if (!privateKey) throw connectorError("CONNECTOR_SIGNING_KEY_REQUIRED", "institution Ed25519 private key is required");
    if (typeof fetchImpl !== "function") throw connectorError("CONNECTOR_TRANSPORT_REQUIRED", "fetch transport is required");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
      throw connectorError("INVALID_CONNECTOR_TIMEOUT", "connector timeout must be 100-60000ms");
    }
    this.endpoint = new URL("/api/institution-callbacks", url).toString();
    this.privateKey = privateKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  createEnvelope({ callbackId, tenantId, institutionId, productId, channel, sequence,
    payload, occurredAt = new Date(), validityMs = 5 * 60 * 1000, keyId = "primary-v1" } = {}) {
    for (const [label, value] of Object.entries({ callbackId, tenantId, institutionId, productId, channel })) {
      bounded(value, label);
    }
    if (!Number.isSafeInteger(sequence) || sequence < 1) {
      throw connectorError("INVALID_CONNECTOR_SEQUENCE", "sequence must be a positive safe integer");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw connectorError("INVALID_CONNECTOR_PAYLOAD", "payload object is required");
    }
    const at = new Date(occurredAt);
    if (!Number.isFinite(at.getTime()) || !Number.isInteger(validityMs) || validityMs < 1_000 || validityMs > 86_400_000) {
      throw connectorError("INVALID_CONNECTOR_TIME", "callback time and validity window are invalid");
    }
    return createSignedCallback({
      callbackId, tenantId, institutionId, productId, channel, sequence, keyId: bounded(keyId, "keyId"),
      eventType: `${channel}.${payload.outcome}`,
      occurredAt: at.toISOString(),
      expiresAt: new Date(at.getTime() + validityMs).toISOString(),
      payloadHash: callbackPayloadHash(payload),
      payload,
    }, this.privateKey);
  }

  async submit(envelope) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(this.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": bounded(envelope?.callbackId, "callbackId"),
        },
        body: JSON.stringify(envelope),
        redirect: "error",
        signal: controller.signal,
      });
    } catch (cause) {
      throw connectorError(cause?.name === "AbortError" ? "CONNECTOR_TIMEOUT" : "CONNECTOR_UNAVAILABLE",
        cause?.name === "AbortError" ? "institution callback timed out" : "institution callback transport failed");
    } finally {
      clearTimeout(timeout);
    }
    const text = await response.text();
    if (text.length > 256 * 1024) throw connectorError("CONNECTOR_RESPONSE_TOO_LARGE", "connector response exceeded limit");
    let body;
    try { body = JSON.parse(text); }
    catch { throw connectorError("INVALID_CONNECTOR_RESPONSE", "connector response was not valid JSON"); }
    if (!response.ok || body?.ok !== true) {
      throw connectorError(body?.code ?? `CONNECTOR_HTTP_${response.status}`, body?.error ?? "institution callback was rejected");
    }
    return body.result;
  }
}
