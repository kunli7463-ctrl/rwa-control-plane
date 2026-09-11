import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadPinnedGroth16Adapter, sha256FileBytes } from "../src/security/snarkjs-verifier.js";

const fixtureDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), "fixtures/groth16-local-only",
);

async function readJson(name) {
  return JSON.parse(await readFile(path.join(fixtureDirectory, name), "utf8"));
}

async function loadFixtureAdapter() {
  const manifestBytes = await readFile(path.join(fixtureDirectory, "manifest.json"));
  return loadPinnedGroth16Adapter({
    bundleDirectory: fixtureDirectory,
    expectedManifestFileHash: sha256FileBytes(manifestBytes),
  });
}

test("official snarkjs verifies the real local-only JoinSplit proof vector", async () => {
  const [adapter, proof, publicSignals, expectedPublicInputs] = await Promise.all([
    loadFixtureAdapter(), readJson("valid_proof.json"), readJson("public_signals.json"),
    readJson("expected_public_inputs.json"),
  ]);
  const receipt = await adapter.verifyJoinSplit({ proof, publicSignals, expectedPublicInputs });
  assert.equal(receipt.verified, true);
  assert.equal(receipt.mode, "GROTH16_VERIFIED");
  assert.equal(receipt.circuitVersion, "2.1.6-local-test-only");
});

test("real Groth16 verification rejects a consistently relabelled public input", async () => {
  const [adapter, proof, publicSignals, expectedPublicInputs] = await Promise.all([
    loadFixtureAdapter(), readJson("valid_proof.json"), readJson("public_signals.json"),
    readJson("expected_public_inputs.json"),
  ]);
  const tamperedSignals = [...publicSignals];
  tamperedSignals[5] = (BigInt(tamperedSignals[5]) + 1n).toString();
  await assert.rejects(adapter.verifyJoinSplit({
    proof,
    publicSignals: tamperedSignals,
    expectedPublicInputs: { ...expectedPublicInputs, relayer: tamperedSignals[5] },
  }), { code: "INVALID_ZERO_KNOWLEDGE_PROOF" });
});

test("real Groth16 verification fails closed on a tampered proof coordinate", async () => {
  const [adapter, proof, publicSignals, expectedPublicInputs] = await Promise.all([
    loadFixtureAdapter(), readJson("valid_proof.json"), readJson("public_signals.json"),
    readJson("expected_public_inputs.json"),
  ]);
  const tamperedProof = structuredClone(proof);
  tamperedProof.pi_a[0] = (BigInt(tamperedProof.pi_a[0]) + 1n).toString();
  await assert.rejects(
    adapter.verifyJoinSplit({ proof: tamperedProof, publicSignals, expectedPublicInputs }),
    (error) => ["INVALID_ZERO_KNOWLEDGE_PROOF", "PROOF_VERIFIER_UNAVAILABLE"].includes(error.code),
  );
});
