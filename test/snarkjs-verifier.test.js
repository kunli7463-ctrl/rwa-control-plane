import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { JOIN_SPLIT_PUBLIC_SIGNAL_ORDER } from "../src/security/proof-adapter.js";
import { loadPinnedGroth16Adapter, sha256FileBytes } from "../src/security/snarkjs-verifier.js";

async function fixture(overrides = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "rwa-groth16-"));
  const verificationKey = { protocol: "groth16", curve: "bn128", alpha: "fixture" };
  const verificationKeyBytes = Buffer.from(JSON.stringify(verificationKey));
  await writeFile(path.join(directory, "verification_key.json"), verificationKeyBytes);
  const manifest = {
    schema: "rwa.groth16-artifact.v1",
    protocol: "groth16",
    curve: "bn128",
    circuitId: "joinsplit-v2-test",
    circuitVersion: "2.0.0-test",
    publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER],
    verificationKey: { path: "verification_key.json", sha256: sha256FileBytes(verificationKeyBytes) },
    ...overrides,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  await writeFile(path.join(directory, "manifest.json"), manifestBytes);
  return { directory, manifest, manifestHash: sha256FileBytes(manifestBytes), verificationKey };
}

test("pinned artifact loader calls snarkjs groth16.verify with all 13 signals", async () => {
  const bundle = await fixture();
  let invocation;
  const adapter = await loadPinnedGroth16Adapter({
    bundleDirectory: bundle.directory,
    expectedManifestFileHash: bundle.manifestHash,
    snarkjsModule: { groth16: { verify: async (...args) => { invocation = args; return true; } } },
  });
  const expectedPublicInputs = Object.fromEntries(
    JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(index + 1)]),
  );
  const publicSignals = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => expectedPublicInputs[name]);
  const proof = {
    protocol: "groth16", curve: "bn128",
    pi_a: ["1", "2", "1"],
    pi_b: [["1", "2"], ["3", "4"], ["1", "0"]],
    pi_c: ["3", "4", "1"],
  };
  const receipt = await adapter.verifyJoinSplit({ proof, publicSignals, expectedPublicInputs });
  assert.equal(receipt.verified, true);
  assert.equal(receipt.manifestHash, bundle.manifestHash);
  assert.deepEqual(invocation, [bundle.verificationKey, publicSignals, proof]);
});

test("snarkjs verifier rejects malformed proof packages before cryptographic work", async () => {
  const bundle = await fixture();
  let called = false;
  const adapter = await loadPinnedGroth16Adapter({
    bundleDirectory: bundle.directory,
    expectedManifestFileHash: bundle.manifestHash,
    snarkjsModule: { groth16: { verify: async () => { called = true; return true; } } },
  });
  const expectedPublicInputs = Object.fromEntries(
    JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(index + 1)]),
  );
  await assert.rejects(adapter.verifyJoinSplit({
    proof: { pi_a: ["1", "2", "1"] },
    publicSignals: JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => expectedPublicInputs[name]),
    expectedPublicInputs,
  }), { code: "PROOF_VERIFIER_UNAVAILABLE" });
  assert.equal(called, false);
});

test("artifact loader fails closed on manifest, key, path and runtime drift", async () => {
  const wrongManifest = await fixture();
  await assert.rejects(loadPinnedGroth16Adapter({
    bundleDirectory: wrongManifest.directory,
    expectedManifestFileHash: "0".repeat(64),
    snarkjsModule: { groth16: { verify: async () => true } },
  }), { code: "ARTIFACT_MANIFEST_HASH_MISMATCH" });

  const wrongKey = await fixture();
  await writeFile(path.join(wrongKey.directory, "verification_key.json"), "{}\n");
  await assert.rejects(loadPinnedGroth16Adapter({
    bundleDirectory: wrongKey.directory,
    expectedManifestFileHash: wrongKey.manifestHash,
    snarkjsModule: { groth16: { verify: async () => true } },
  }), { code: "VERIFICATION_KEY_FILE_HASH_MISMATCH" });

  const escaped = await fixture();
  const outsideName = `${path.basename(escaped.directory)}-outside.json`;
  const outsideBytes = Buffer.from(JSON.stringify(escaped.verificationKey));
  await writeFile(path.join(path.dirname(escaped.directory), outsideName), outsideBytes);
  const escapedManifest = {
    ...escaped.manifest,
    verificationKey: { path: `../${outsideName}`, sha256: sha256FileBytes(outsideBytes) },
  };
  const escapedManifestBytes = Buffer.from(JSON.stringify(escapedManifest));
  await writeFile(path.join(escaped.directory, "manifest.json"), escapedManifestBytes);
  await assert.rejects(loadPinnedGroth16Adapter({
    bundleDirectory: escaped.directory,
    expectedManifestFileHash: sha256FileBytes(escapedManifestBytes),
    snarkjsModule: { groth16: { verify: async () => true } },
  }), { code: "ARTIFACT_PATH_ESCAPE" });

  const invalidRuntime = await fixture();
  await assert.rejects(loadPinnedGroth16Adapter({
    bundleDirectory: invalidRuntime.directory,
    expectedManifestFileHash: invalidRuntime.manifestHash,
    snarkjsModule: {},
  }), { code: "INVALID_SNARKJS_MODULE" });
});
