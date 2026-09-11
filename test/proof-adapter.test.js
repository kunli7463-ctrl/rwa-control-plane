import assert from "node:assert/strict";
import test from "node:test";
import {
  Groth16JoinSplitProofAdapter, JOIN_SPLIT_PUBLIC_SIGNAL_ORDER,
  SandboxNoProofAdapter, verificationKeyHash,
} from "../src/security/proof-adapter.js";

function fixture(overrides = {}) {
  const verificationKey = { protocol: "groth16", curve: "bn128", vk_alpha_1: ["1", "2", "1"] };
  const manifest = {
    protocol: "groth16", curve: "bn128", circuitId: "confidential-ledger-joinsplit",
    circuitVersion: "2.0.0-audit-candidate", publicSignalOrder: [...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER],
  };
  const expectedPublicInputs = Object.fromEntries(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name, index) => [name, String(index + 1)]));
  const publicSignals = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => expectedPublicInputs[name]);
  return { verificationKey, manifest, expectedPublicInputs, publicSignals, proof: { pi_a: ["1", "2", "1"] }, ...overrides };
}

test("Groth16 adapter pins artifact, signal order and every authorized public input", async () => {
  const data = fixture();
  const verifier = { async verify(_key, signals) { return signals.length === 13; } };
  const adapter = new Groth16JoinSplitProofAdapter({
    verifier, verificationKey: data.verificationKey, manifest: data.manifest,
    expectedVerificationKeyHash: verificationKeyHash(data.verificationKey),
  });
  const receipt = await adapter.verifyJoinSplit(data);
  assert.equal(receipt.verified, true);
  assert.equal(receipt.circuitVersion, "2.0.0-audit-candidate");
  assert.match(receipt.proofHash, /^[0-9a-f]{64}$/);
  for (let index = 0; index < data.publicSignals.length; index += 1) {
    const tampered = [...data.publicSignals];
    tampered[index] = String(100 + index);
    await assert.rejects(adapter.verifyJoinSplit({ ...data, publicSignals: tampered }), {
      code: "PROOF_CONTEXT_MISMATCH",
    });
  }
});

test("Groth16 adapter rejects artifact drift, order drift, invalid proof and verifier outage", async () => {
  const data = fixture();
  assert.throws(() => new Groth16JoinSplitProofAdapter({
    verifier: { verify: async () => true }, verificationKey: data.verificationKey, manifest: data.manifest,
    expectedVerificationKeyHash: "0".repeat(64),
  }), { code: "VERIFICATION_KEY_HASH_MISMATCH" });
  assert.throws(() => new Groth16JoinSplitProofAdapter({
    verifier: { verify: async () => true }, verificationKey: data.verificationKey,
    manifest: { ...data.manifest, publicSignalOrder: [...data.manifest.publicSignalOrder].reverse() },
    expectedVerificationKeyHash: verificationKeyHash(data.verificationKey),
  }), { code: "PUBLIC_SIGNAL_ORDER_MISMATCH" });
  const rejected = new Groth16JoinSplitProofAdapter({
    verifier: { verify: async () => false }, verificationKey: data.verificationKey, manifest: data.manifest,
    expectedVerificationKeyHash: verificationKeyHash(data.verificationKey),
  });
  await assert.rejects(rejected.verifyJoinSplit(data), { code: "INVALID_ZERO_KNOWLEDGE_PROOF" });
  const unavailable = new Groth16JoinSplitProofAdapter({
    verifier: { verify: async () => { throw new Error("offline"); } }, verificationKey: data.verificationKey,
    manifest: data.manifest, expectedVerificationKeyHash: verificationKeyHash(data.verificationKey),
  });
  await assert.rejects(unavailable.verifyJoinSplit(data), { code: "PROOF_VERIFIER_UNAVAILABLE" });
});

test("sandbox proof adapter cannot be mistaken for verified production proof", async () => {
  assert.deepEqual(await new SandboxNoProofAdapter().verifyJoinSplit(), {
    verified: false, mode: "SANDBOX_NO_ZK_PROOF", productionAcceptable: false,
  });
});

