import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { JOIN_SPLIT_PUBLIC_SIGNAL_ORDER } from "../src/security/proof-adapter.js";

const referencePath = process.env.REFERENCE_V2_PATH;
const outputPath = process.env.ZK_INPUT_OUTPUT_PATH;

if (!referencePath || !outputPath) {
  throw new Error("REFERENCE_V2_PATH and ZK_INPUT_OUTPUT_PATH are required");
}

const requireFromReference = createRequire(pathToFileURL(path.resolve(referencePath)));
const ref = requireFromReference(path.resolve(referencePath));
await ref.init();

const contextId = ref.makeContextId({
  protocolId: 1n,
  ledgerId: 42n,
  chainId: 1n,
  contractAddress: BigInt("0x00000000000000000000000000000000deadbeef"),
  version: 2n,
});
const assetType = 7n;
const ownerSecretA = (1n << 200n) + 11n;
const ownerSecretB = (1n << 190n) + 22n;
const ownerPublicKeyA = ref.ownerPubKey(ownerSecretA);
const ownerPublicKeyB = ref.ownerPubKey(ownerSecretB);
const recipientPublicKey = ref.ownerPubKey(12345n);

const inputA = ref.makeNote({
  amount: 700n, assetType, ownerPubKey: ownerPublicKeyA, nonce: 1n,
  blinding: (1n << 247n) - 1n,
});
const inputB = ref.makeNote({
  amount: 300n, assetType, ownerPubKey: ownerPublicKeyB, nonce: 2n, blinding: 999n,
});
const filler = ref.makeNote({
  amount: 5n, assetType, ownerPubKey: ownerPublicKeyA, nonce: 3n, blinding: 7n,
});
const tree = ref.buildTree([
  ref.commitmentHash(inputA), ref.commitmentHash(filler), ref.commitmentHash(inputB),
]);
const outputA = ref.makeNote({
  amount: 950n, assetType, ownerPubKey: recipientPublicKey, nonce: 10n, blinding: 111n,
});
const outputB = ref.makeNote({
  amount: 45n, assetType, ownerPubKey: ownerPublicKeyA, nonce: 11n, blinding: 222n,
});
const joinSplit = ref.buildJoinSplit({
  inputs: [
    { note: inputA, ownerSecret: ownerSecretA, index: 0 },
    { note: inputB, ownerSecret: ownerSecretB, index: 2 },
  ],
  outputs: [outputA, outputB],
  tree,
  contextId,
  assetType,
  fee: 5n,
  recipient: BigInt("0x000000000000000000000000000000000000cafe"),
  relayer: BigInt("0x000000000000000000000000000000000000beef"),
});

const expectedPublicInputs = {
  merkleRoot: joinSplit.input.merkleRoot,
  contextId: joinSplit.input.contextId,
  assetType: joinSplit.input.assetType,
  fee: joinSplit.input.fee,
  recipient: joinSplit.input.recipient,
  relayer: joinSplit.input.relayer,
  transactionHash: joinSplit.input.transactionHash,
  inputNullifier0: joinSplit.input.inputNullifiers[0],
  inputNullifier1: joinSplit.input.inputNullifiers[1],
  outputCommitmentX0: joinSplit.input.outputCommitmentX[0],
  outputCommitmentX1: joinSplit.input.outputCommitmentX[1],
  outputCommitmentY0: joinSplit.input.outputCommitmentY[0],
  outputCommitmentY1: joinSplit.input.outputCommitmentY[1],
};

await writeFile(outputPath, `${JSON.stringify({
  circuitInput: joinSplit.input,
  expectedPublicInputs,
  expectedPublicSignals: JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => expectedPublicInputs[name]),
}, null, 2)}\n`);
console.log(`wrote deterministic local-only Groth16 input fixture to ${outputPath}`);
