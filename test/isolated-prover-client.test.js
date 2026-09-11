import assert from "node:assert/strict";
import test from "node:test";
import { IsolatedProverClient } from "../src/security/isolated-prover-client.js";

const token = "t".repeat(64);
const baseRequest = {
  requestId: "request-1", transactionId: "transaction-1", circuitId: "joinsplit",
  circuitVersion: "3.0.0", authorizationHash: "ab".repeat(32), witnessReference: "vault://rwa/witness/opaque-1",
};

function response(body, { status = 200, serviceId = "prover-hk-1" } = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "x-rwa-prover-id": serviceId } });
}

test("isolated prover requires HTTPS, pinned identity and an opaque witness reference", async () => {
  assert.throws(() => new IsolatedProverClient({ endpoint: "http://prover.test", serviceToken: token,
    expectedServiceId: "prover-hk-1" }), { code: "INVALID_PROVER_ENDPOINT" });
  const client = new IsolatedProverClient({ endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", transport: async () => response({
      schema: "rwa.prover-job-status.v1", jobId: "job-1", state: "QUEUED",
    }) });
  await assert.rejects(client.submitJob({ ...baseRequest, witnessReference: "raw-secret" }), {
    code: "INVALID_WITNESS_REFERENCE",
  });
  assert.deepEqual(await client.submitJob(baseRequest), { jobId: "job-1", state: "QUEUED" });
});

test("isolated prover sends no raw witness and binds an idempotent authorization digest", async () => {
  let captured;
  const client = new IsolatedProverClient({ endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", transport: async (url, options) => {
      captured = { url: url.toString(), options, body: JSON.parse(options.body) };
      return response({ schema: "rwa.prover-job-status.v1", jobId: "job-1", state: "RUNNING" });
    } });
  await client.submitJob(baseRequest);
  assert.equal(captured.url, "https://prover.test/v1/jobs");
  assert.equal(captured.options.headers["idempotency-key"], "request-1");
  assert.equal(captured.body.authorizationHash, baseRequest.authorizationHash);
  assert.equal(captured.body.witnessReference, baseRequest.witnessReference);
  assert.equal("witness" in captured.body, false);
});

test("isolated prover validates service identity, job state and the 13-signal proof package", async () => {
  const signals = Array.from({ length: 13 }, (_, index) => String(index + 1));
  const valid = new IsolatedProverClient({ endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", transport: async () => response({
      schema: "rwa.prover-job-status.v1", jobId: "job-1", state: "SUCCEEDED",
      result: { proof: { protocol: "groth16" }, publicSignals: signals },
    }) });
  assert.deepEqual(await valid.getJob("job-1"), {
    jobId: "job-1", state: "SUCCEEDED", proof: { protocol: "groth16" }, publicSignals: signals,
  });
  const wrongIdentity = new IsolatedProverClient({ endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", transport: async () => response({}, { serviceId: "unknown" }) });
  await assert.rejects(wrongIdentity.getJob("job-1"), { code: "PROVER_IDENTITY_MISMATCH" });
  const malformed = new IsolatedProverClient({ endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", transport: async () => response({
      schema: "rwa.prover-job-status.v1", jobId: "job-1", state: "SUCCEEDED",
      result: { proof: {}, publicSignals: ["1"] },
    }) });
  await assert.rejects(malformed.getJob("job-1"), { code: "INVALID_PROVER_RESPONSE" });
});

test("isolated prover aborts a stalled request at the configured deadline", async () => {
  const client = new IsolatedProverClient({
    endpoint: "https://prover.test/v1", serviceToken: token,
    expectedServiceId: "prover-hk-1", timeoutMs: 1_000,
    transport: async (_url, { signal }) => new Promise((_resolve, reject) => {
      // A real stalled HTTP socket keeps the event loop alive. Mirror that
      // property so the client's deliberately unref'ed deadline can fire.
      const stalledSocket = setTimeout(() => {}, 5_000);
      signal.addEventListener("abort", () => {
        clearTimeout(stalledSocket);
        const error = new Error("aborted by deadline");
        error.name = "AbortError";
        reject(error);
      }, { once: true });
    }),
  });
  const started = Date.now();
  await assert.rejects(client.getJob("job-timeout"), { code: "PROVER_SERVICE_TIMEOUT" });
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 900 && elapsed < 2_500, `timeout elapsed ${elapsed}ms`);
});
