// Local-only evidence for audit finding H1 (recipient binding).
//
// Requires circuits compiled by the operator, for example:
//   circom zk-candidate/circuits/confidential_ledger_v2.circom --r1cs --wasm -l node_modules -o $WORK/v2
//   circom zk-candidate/circuits/confidential_ledger_v3.circom --r1cs --wasm -l node_modules -o $WORK/v3
//   ZK_V3_WORK_DIR=$WORK node scripts/verify-zk-v3-recipient-binding.js
//
// It shows that v2 accepts a witness whose value goes to a key other than
// the public recipient, that v3 rejects it, and that an honest v3 transfer
// proves and verifies end to end. The ceremony here is a throwaway
// single-party test setup: never deploy its keys.
import { createRequire } from "node:module";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { getCurveFromName } from "ffjavascript";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const work = process.env.ZK_V3_WORK_DIR;
if (!work) throw new Error("ZK_V3_WORK_DIR is required");
const reference = require(path.join(root, "zk-candidate/scripts/reference_v3.js"));
await reference.init();

const artifacts = (version) => ({
  wasm: path.join(work, version, `confidential_ledger_${version}_js`, `confidential_ledger_${version}.wasm`),
  r1cs: path.join(work, version, `confidential_ledger_${version}.r1cs`),
});

function scenario({ recipientKey, changeOwner }) {
  const assetType = 7n;
  const ownerSecretA = (1n << 200n) + 11n;
  const ownerSecretB = (1n << 190n) + 22n;
  const ownerA = reference.ownerPubKey(ownerSecretA);
  const ownerB = reference.ownerPubKey(ownerSecretB);
  const inputA = reference.makeNote({ amount: 700n, assetType, ownerPubKey: ownerA, nonce: 1n, blinding: (1n << 247n) - 1n });
  const inputB = reference.makeNote({ amount: 300n, assetType, ownerPubKey: ownerB, nonce: 2n, blinding: 999n });
  const filler = reference.makeNote({ amount: 5n, assetType, ownerPubKey: ownerA, nonce: 3n, blinding: 7n });
  const tree = reference.buildTree([inputA, filler, inputB].map(reference.commitmentHash));
  const contextId = reference.makeContextId({
    protocolId: 1n, ledgerId: 42n, chainId: 1n, contractAddress: 0xdeadbeefn, version: 3n,
  });
  const authorizedRecipient = reference.ownerPubKey(12345n);
  const outputs = [
    reference.makeNote({ amount: 950n, assetType, ownerPubKey: recipientKey ?? authorizedRecipient, nonce: 10n, blinding: 111n }),
    reference.makeNote({ amount: 45n, assetType, ownerPubKey: changeOwner ?? ownerA, nonce: 11n, blinding: 222n }),
  ];
  const args = {
    inputs: [{ note: inputA, ownerSecret: ownerSecretA, index: 0 }, { note: inputB, ownerSecret: ownerSecretB, index: 2 }],
    outputs, tree, contextId, assetType, fee: 5n, recipient: authorizedRecipient, relayer: 0xbeefn,
  };
  // Bypass the reference-side v3 guard so the circuit itself is exercised.
  const { buildJoinSplit } = require(path.join(root, "zk-candidate/scripts/reference_v2.js"));
  return buildJoinSplit(args).input;
}

async function witnessAccepted(version, input) {
  const { wasm } = artifacts(version);
  try {
    await snarkjs.wtns.calculate(input, wasm, { type: "mem" });
    return true;
  } catch {
    return false;
  }
}

const attackerKey = reference.ownerPubKey(666n);
const honest = scenario({});
const redirectedValue = scenario({ recipientKey: attackerKey });
const redirectedChange = scenario({ changeOwner: attackerKey });

console.error(`[witness checks] ${new Date().toISOString()}`);
const results = {
  v2AcceptsRedirectedValue: await witnessAccepted("v2", redirectedValue),
  v3RejectsRedirectedValue: !(await witnessAccepted("v3", redirectedValue)),
  v3RejectsRedirectedChange: !(await witnessAccepted("v3", redirectedChange)),
  v3AcceptsHonestTransfer: await witnessAccepted("v3", honest),
};

const ceremony = path.join(work, "v3-local-ceremony");
await mkdir(ceremony, { recursive: true });
const curve = await getCurveFromName("bn128");
const ptau0 = path.join(ceremony, "UNSAFE_TEST_ONLY_0000.ptau");
const ptau1 = path.join(ceremony, "UNSAFE_TEST_ONLY_0001.ptau");
const ptauFinal = path.join(ceremony, "UNSAFE_TEST_ONLY_final.ptau");
const zkey0 = path.join(ceremony, "UNSAFE_TEST_ONLY_0000.zkey");
const zkeyFinal = path.join(ceremony, "UNSAFE_TEST_ONLY_final.zkey");
console.error(`[ptau new] ${new Date().toISOString()}`);
await snarkjs.powersOfTau.newAccumulator(curve, 15, ptau0);
console.error(`[ptau contribute] ${new Date().toISOString()}`);
await snarkjs.powersOfTau.contribute(ptau0, ptau1, "unsafe-local", `entropy-${Date.now()}-${Math.random()}`);
console.error(`[ptau prepare] ${new Date().toISOString()}`);
await snarkjs.powersOfTau.preparePhase2(ptau1, ptauFinal);
console.error(`[zkey new] ${new Date().toISOString()}`);
await snarkjs.zKey.newZKey(artifacts("v3").r1cs, ptauFinal, zkey0);
console.error(`[zkey contribute] ${new Date().toISOString()}`);
await snarkjs.zKey.contribute(zkey0, zkeyFinal, "unsafe-local", `entropy-${Date.now()}-${Math.random()}`);
const verificationKey = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
console.error(`[prove] ${new Date().toISOString()}`);
const { proof, publicSignals } = await snarkjs.groth16.fullProve(honest, artifacts("v3").wasm, zkeyFinal);
results.v3HonestProofVerifies = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
results.v3PublicSignalCount = publicSignals.length;
results.v3RecipientSignalIsOutputOwner = publicSignals[4] === reference.ownerPubKey(12345n).toString();
const relabelled = [...publicSignals];
relabelled[4] = attackerKey.toString();
results.v3RelabelledRecipientRejected = !(await snarkjs.groth16.verify(verificationKey, relabelled, proof));
await curve.terminate();

await writeFile(path.join(work, "v3-recipient-binding-evidence.json"), `${JSON.stringify(results, null, 2)}\n`);
console.log(JSON.stringify(results, null, 2));
const ok = Object.entries(results).every(([key, value]) => (key === "v3PublicSignalCount" ? value === 13 : value === true));
if (!ok) {
  console.error("V3_RECIPIENT_BINDING_FAILED");
  process.exit(1);
}
console.log("V3_RECIPIENT_BINDING_OK");
process.exit(0);
