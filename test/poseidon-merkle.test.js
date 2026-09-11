import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildPoseidon } from "circomlibjs";
import {
  appendMerkleLeaves, emptyMerkleTreeState, merkleLeaf, merkleRootFromFrontier,
  MERKLE_TREE_DEPTH, poseidon3,
} from "../src/security/poseidon-merkle.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

async function referenceImplementation() {
  const reference = require(path.resolve(here, "../zk-candidate/scripts/reference_v2.js"));
  await reference.init();
  return reference;
}

test("dependency-free Poseidon(3) matches circomlibjs", async () => {
  const poseidon = await buildPoseidon();
  const vectors = [
    [0n, 0n, 0n],
    [1n, 2n, 3n],
    [0x434c324e4f444501n, 123456789n, 987654321n],
    [2n ** 253n + 17n, 2n ** 200n + 5n, 21888242871839275222246405745257275088548364400416034343698204186575808495616n],
  ];
  for (const inputs of vectors) {
    const expected = poseidon.F.toObject(poseidon(inputs.map((value) => poseidon.F.e(value))));
    assert.equal(poseidon3(...inputs), expected);
  }
});

test("incremental frontier appends reproduce the reference fixed-depth tree", async () => {
  const reference = await referenceImplementation();
  let state = emptyMerkleTreeState();
  assert.equal(state.root, reference.buildTree([]).root.toString());
  const leaves = [];
  for (let index = 0; index < 9; index += 1) {
    const leaf = reference.H([reference.MERKLE_LEAF_DOMAIN, BigInt(index + 11), BigInt(index + 97)]);
    assert.equal(merkleLeaf(index + 11, index + 97), leaf);
    leaves.push(leaf);
    state = appendMerkleLeaves({ ...state, expectedRoot: state.root }, [leaf]);
    assert.equal(state.treeSize, index + 1);
    assert.equal(state.root, reference.buildTree(leaves).root.toString());
    assert.equal(merkleRootFromFrontier(state.treeSize, state.frontier).toString(), state.root);
  }
  const batched = appendMerkleLeaves(emptyMerkleTreeState(), leaves);
  assert.deepEqual(batched, state);
  assert.equal(state.frontier.length, MERKLE_TREE_DEPTH);
});

test("the server tree reproduces the root accepted by the real Groth16 fixture", async () => {
  const reference = await referenceImplementation();
  const expected = JSON.parse(await readFile(
    path.resolve(here, "fixtures/groth16-local-only/expected_public_inputs.json"), "utf8",
  ));
  const assetType = 7n;
  const ownerA = reference.ownerPubKey((1n << 200n) + 11n);
  const ownerB = reference.ownerPubKey((1n << 190n) + 22n);
  const notes = [
    reference.makeNote({ amount: 700n, assetType, ownerPubKey: ownerA, nonce: 1n, blinding: (1n << 247n) - 1n }),
    reference.makeNote({ amount: 5n, assetType, ownerPubKey: ownerA, nonce: 3n, blinding: 7n }),
    reference.makeNote({ amount: 300n, assetType, ownerPubKey: ownerB, nonce: 2n, blinding: 999n }),
  ];
  const inputTree = appendMerkleLeaves(emptyMerkleTreeState(), notes.map((note) => {
    const [x, y] = reference.noteCommitment(note);
    return merkleLeaf(x, y).toString();
  }));
  assert.equal(inputTree.root, expected.merkleRoot);
  const outputTree = appendMerkleLeaves({ ...inputTree, expectedRoot: expected.merkleRoot }, [
    merkleLeaf(expected.outputCommitmentX0, expected.outputCommitmentY0).toString(),
    merkleLeaf(expected.outputCommitmentX1, expected.outputCommitmentY1).toString(),
  ]);
  assert.equal(outputTree.treeSize, 5);
  assert.notEqual(outputTree.root, inputTree.root);
});

test("frontier validation fails closed on malformed or inconsistent state", () => {
  const empty = emptyMerkleTreeState();
  assert.throws(() => merkleRootFromFrontier(1, empty.frontier), { code: "INVALID_MERKLE_TREE_STATE" });
  assert.throws(() => merkleRootFromFrontier(0, ["1", ...empty.frontier.slice(1)]), { code: "INVALID_MERKLE_TREE_STATE" });
  assert.throws(() => merkleRootFromFrontier(-1, empty.frontier), { code: "INVALID_MERKLE_TREE_STATE" });
  assert.throws(() => merkleRootFromFrontier(0, empty.frontier.slice(1)), { code: "INVALID_MERKLE_TREE_STATE" });
  const one = appendMerkleLeaves(empty, ["5"]);
  assert.throws(() => appendMerkleLeaves({ ...one, expectedRoot: "1" }, ["6"]), { code: "MERKLE_FRONTIER_ROOT_MISMATCH" });
  assert.throws(() => appendMerkleLeaves(one, [BN254_OVERFLOW]), { code: "INVALID_PUBLIC_SIGNAL" });
});

const BN254_OVERFLOW = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
