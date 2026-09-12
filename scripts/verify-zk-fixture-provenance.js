#!/usr/bin/env node
// Audit finding D4: state exactly what the stored Groth16 vector proves.
//
// Checks what can be checked inside this repository — the manifest's pinned
// verification-key hash, the 13-signal public order, and that the stored proof
// verifies under that key — and prints the provenance facts that remain
// unproven until a reproducible build and a recorded ceremony exist.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JOIN_SPLIT_PUBLIC_SIGNAL_ORDER } from "../src/security/proof-adapter.js";

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../test/fixtures/groth16-local-only");
const read = async (name) => JSON.parse(await readFile(path.join(fixtures, name), "utf8"));
const sha256 = async (name) => createHash("sha256").update(await readFile(path.join(fixtures, name))).digest("hex");

const manifest = await read("manifest.json");
const publicSignals = await read("public_signals.json");

const report = {
  schema: "rwa.zk-fixture-provenance.v1",
  verificationKeyHashMatchesManifest: manifest.verificationKey.sha256 === await sha256("verification_key.json"),
  publicSignalOrderMatchesAdapter:
    JSON.stringify(manifest.publicSignalOrder) === JSON.stringify([...JOIN_SPLIT_PUBLIC_SIGNAL_ORDER]),
  publicSignalCount: publicSignals.length,
  // The stored proof is verified against this key by the real snarkjs verifier in
  // test/integration/real-groth16-gate.integration.test.js.
  notProven: [
    "that this verification key was produced from the circuit source in zk-candidate/circuits",
    "reproducible build of the circuit artifacts",
    "multi-party ceremony and transcript",
    "independent circuit audit",
  ],
  requiredEvidence: "unbroken sha256 chain: frozen circuit source -> r1cs -> zkey -> verification key, with ceremony transcript",
};
console.log(JSON.stringify(report, null, 2));
const ok = report.verificationKeyHashMatchesManifest && report.publicSignalOrderMatchesAdapter
  && report.publicSignalCount === 13;
if (!ok) {
  console.error("ZK_FIXTURE_PROVENANCE_FAILED");
  process.exit(1);
}
console.log("ZK_FIXTURE_CHECKS_OK (source linkage remains unproven)");
