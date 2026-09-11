import { randomUUID } from "node:crypto";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const FIELD = /^(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;

function proverError(code, message, cause = undefined) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function boundedIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw proverError("INVALID_PROVER_REQUEST", `${label} is not a bounded canonical identifier`);
  }
  return value;
}

function validateWitnessReference(value) {
  if (typeof value !== "string" || value.length > 500
      || !/^(vault|hsm|kmsref):\/\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value)) {
    throw proverError("INVALID_WITNESS_REFERENCE", "witnessReference must be an opaque vault, HSM or KMS reference");
  }
  return value;
}

function validateProofPackage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || !value.proof || !Array.isArray(value.publicSignals) || value.publicSignals.length !== 13
      || !value.publicSignals.every((signal) => typeof signal === "string" && FIELD.test(signal))) {
    throw proverError("INVALID_PROVER_RESPONSE", "completed prover job must return a proof and exactly 13 canonical public signals");
  }
  return { proof: value.proof, publicSignals: value.publicSignals };
}

async function boundedJson(response) {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw proverError("PROVER_RESPONSE_TOO_LARGE", "prover response exceeds the configured size limit");
  }
  let body;
  try { body = JSON.parse(text); }
  catch (cause) { throw proverError("INVALID_PROVER_RESPONSE", "prover response is not valid JSON", cause); }
  if (!response.ok) {
    throw proverError("PROVER_SERVICE_REJECTED", `prover service rejected the request with status ${response.status}`);
  }
  return body;
}

export class IsolatedProverClient {
  constructor({ endpoint, serviceToken, expectedServiceId, timeoutMs = 15_000, transport = fetch } = {}) {
    let base;
    try { base = new URL(endpoint); } catch { /* validated below */ }
    if (!base || base.protocol !== "https:" || base.username || base.password || base.search || base.hash) {
      throw proverError("INVALID_PROVER_ENDPOINT", "isolated prover endpoint must be an exact HTTPS origin or path without credentials or query data");
    }
    if (typeof serviceToken !== "string" || serviceToken.length < 32 || serviceToken.length > 4096) {
      throw proverError("INVALID_PROVER_CREDENTIAL", "isolated prover service token must be between 32 and 4096 characters");
    }
    if (!IDENTIFIER.test(expectedServiceId ?? "")) {
      throw proverError("INVALID_PROVER_IDENTITY", "expected prover service identity is required");
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
      throw proverError("INVALID_PROVER_TIMEOUT", "prover request timeout must be between 1 and 120 seconds");
    }
    if (typeof transport !== "function") throw proverError("INVALID_PROVER_TRANSPORT", "prover transport is required");
    this.endpoint = new URL(base.toString().replace(/\/$/, ""));
    this.serviceToken = serviceToken;
    this.expectedServiceId = expectedServiceId;
    this.timeoutMs = timeoutMs;
    this.transport = transport;
  }

  async submitJob({ requestId = randomUUID(), transactionId, circuitId, circuitVersion,
    authorizationHash, witnessReference }) {
    const request = {
      schema: "rwa.prover-job.v1",
      requestId: boundedIdentifier(requestId, "requestId"),
      transactionId: boundedIdentifier(transactionId, "transactionId"),
      circuitId: boundedIdentifier(circuitId, "circuitId"),
      circuitVersion: boundedIdentifier(circuitVersion, "circuitVersion"),
      authorizationHash: SHA256.test(authorizationHash ?? "") ? authorizationHash : null,
      witnessReference: validateWitnessReference(witnessReference),
    };
    if (!request.authorizationHash) throw proverError("INVALID_PROVER_REQUEST", "authorizationHash must be a lowercase SHA-256 digest");
    const body = await this.#request("jobs", { method: "POST", body: JSON.stringify(request), idempotencyKey: request.requestId });
    if (body.schema !== "rwa.prover-job-status.v1" || !IDENTIFIER.test(body.jobId ?? "")
        || !new Set(["QUEUED", "RUNNING"]).has(body.state)) {
      throw proverError("INVALID_PROVER_RESPONSE", "prover submission response has an invalid job identity or state");
    }
    return { jobId: body.jobId, state: body.state };
  }

  async getJob(jobId) {
    boundedIdentifier(jobId, "jobId");
    const body = await this.#request(`jobs/${encodeURIComponent(jobId)}`, { method: "GET" });
    if (body.schema !== "rwa.prover-job-status.v1" || body.jobId !== jobId
        || !new Set(["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"]).has(body.state)) {
      throw proverError("INVALID_PROVER_RESPONSE", "prover status response has an invalid identity or state");
    }
    if (body.state === "SUCCEEDED") return { jobId, state: body.state, ...validateProofPackage(body.result) };
    if (body.state === "FAILED") {
      const errorCode = typeof body.errorCode === "string" && /^[A-Z][A-Z0-9_]{0,79}$/.test(body.errorCode)
        ? body.errorCode : "PROVER_JOB_FAILED";
      return { jobId, state: body.state, errorCode };
    }
    return { jobId, state: body.state };
  }

  async #request(relativePath, { method, body = undefined, idempotencyKey = undefined }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    timer.unref();
    try {
      const response = await this.transport(new URL(relativePath, `${this.endpoint.toString()}/`), {
        method,
        redirect: "error",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.serviceToken}`,
          ...(body ? { "content-type": "application/json" } : {}),
          ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
        },
        body,
      });
      if (response.headers.get("x-rwa-prover-id") !== this.expectedServiceId) {
        throw proverError("PROVER_IDENTITY_MISMATCH", "prover response identity does not match the deployment pin");
      }
      return await boundedJson(response);
    } catch (cause) {
      if (cause?.name === "AbortError") throw proverError("PROVER_SERVICE_TIMEOUT", "isolated prover request timed out", cause);
      if (cause?.code) throw cause;
      throw proverError("PROVER_SERVICE_UNAVAILABLE", "isolated prover service is unavailable", cause);
    } finally {
      clearTimeout(timer);
    }
  }
}

