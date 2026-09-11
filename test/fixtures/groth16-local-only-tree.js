import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appendMerkleLeaves, emptyMerkleTreeState, merkleLeaf } from "../../src/security/poseidon-merkle.js";

// Rebuilds the three-note input tree used by scripts/generate-local-groth16-input.js
// so integration tests can register the fixture root together with the frontier
// that reproduces it. Test-only: relies on the circomlibjs dev dependency.
const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

export async function localGroth16InputTree() {
  const reference = require(path.resolve(here, "../../zk-candidate/scripts/reference_v2.js"));
  await reference.init();
  const assetType = 7n;
  const ownerA = reference.ownerPubKey((1n << 200n) + 11n);
  const ownerB = reference.ownerPubKey((1n << 190n) + 22n);
  const notes = [
    reference.makeNote({ amount: 700n, assetType, ownerPubKey: ownerA, nonce: 1n, blinding: (1n << 247n) - 1n }),
    reference.makeNote({ amount: 5n, assetType, ownerPubKey: ownerA, nonce: 3n, blinding: 7n }),
    reference.makeNote({ amount: 300n, assetType, ownerPubKey: ownerB, nonce: 2n, blinding: 999n }),
  ];
  return appendMerkleLeaves(emptyMerkleTreeState(), notes.map((note) => {
    const [x, y] = reference.noteCommitment(note);
    return merkleLeaf(x, y).toString();
  }));
}
