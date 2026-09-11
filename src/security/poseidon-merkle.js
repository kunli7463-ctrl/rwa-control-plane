import { createRequire } from "node:module";
import { BN254_SCALAR_FIELD, normalizeFieldElement } from "./proof-adapter.js";

// Server-side incremental Merkle tree for the confidential note ledger.
//
// It mirrors zk-candidate/circuits/confidential_ledger_v2.circom exactly:
//   leaf(x, y)        = Poseidon([MERKLE_LEAF_DOMAIN, x, y])
//   node(left, right) = Poseidon([MERKLE_NODE_DOMAIN, left, right])
//   zeros[0] = 0, zeros[k+1] = node(zeros[k], zeros[k]), depth 32
//
// The tree state is a "frontier": for every set bit i of treeSize, frontier[i]
// is the root of the complete left subtree of 2^i leaves at that level; unset
// bits hold null. The frontier plus the size determine the root, so a
// published root can be recomputed and an append can be verified without
// storing every leaf.

const require = createRequire(import.meta.url);
const CONSTANTS = require("./poseidon-bn254-t4-constants.json");

const P = BN254_SCALAR_FIELD;
export const MERKLE_TREE_DEPTH = 32;
export const MERKLE_LEAF_DOMAIN = 0x434c324c45414601n; // "CL2LEAF\x01"
export const MERKLE_NODE_DOMAIN = 0x434c324e4f444501n; // "CL2NODE\x01"
const MAX_TREE_SIZE = 2n ** BigInt(MERKLE_TREE_DEPTH);

const T = CONSTANTS.t;
const ROUNDS_F = CONSTANTS.nRoundsF;
const ROUNDS_P = CONSTANTS.nRoundsP;
const C = CONSTANTS.C.map((value) => BigInt(value));
const M = CONSTANTS.M.map((row) => row.map((value) => BigInt(value)));
if (T !== 4 || C.length !== T * (ROUNDS_F + ROUNDS_P) || M.length !== T) {
  throw new Error("Poseidon t=4 constants are malformed");
}

function treeError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function mod(value) {
  const reduced = value % P;
  return reduced < 0n ? reduced + P : reduced;
}

function pow5(value) {
  const square = (value * value) % P;
  return (((square * square) % P) * value) % P;
}

/** Poseidon over BN254 with exactly three inputs (circomlib Poseidon(3)). */
export function poseidon3(a, b, c) {
  let state = [0n, mod(BigInt(a)), mod(BigInt(b)), mod(BigInt(c))];
  for (let round = 0; round < ROUNDS_F + ROUNDS_P; round += 1) {
    for (let i = 0; i < T; i += 1) state[i] = mod(state[i] + C[round * T + i]);
    if (round < ROUNDS_F / 2 || round >= ROUNDS_F / 2 + ROUNDS_P) {
      for (let i = 0; i < T; i += 1) state[i] = pow5(state[i]);
    } else {
      state[0] = pow5(state[0]);
    }
    const mixed = new Array(T);
    for (let i = 0; i < T; i += 1) {
      let accumulator = 0n;
      for (let j = 0; j < T; j += 1) accumulator += M[i][j] * state[j];
      mixed[i] = accumulator % P;
    }
    state = mixed;
  }
  return state[0];
}

export function merkleLeaf(commitmentX, commitmentY) {
  return poseidon3(MERKLE_LEAF_DOMAIN, BigInt(commitmentX), BigInt(commitmentY));
}

export function merkleNode(left, right) {
  return poseidon3(MERKLE_NODE_DOMAIN, BigInt(left), BigInt(right));
}

let zeroCache = null;
export function merkleZeros() {
  if (!zeroCache) {
    zeroCache = [0n];
    for (let level = 1; level <= MERKLE_TREE_DEPTH; level += 1) {
      zeroCache.push(merkleNode(zeroCache[level - 1], zeroCache[level - 1]));
    }
    Object.freeze(zeroCache);
  }
  return zeroCache;
}

function parseTreeSize(value) {
  let size;
  try { size = BigInt(value); } catch { size = -1n; }
  if (size < 0n || size >= MAX_TREE_SIZE) {
    throw treeError("INVALID_MERKLE_TREE_STATE", "tree size must be an integer in [0, 2^32)");
  }
  return size;
}

/** Validates and normalizes a stored frontier into bigint-or-null entries. */
export function parseMerkleFrontier(treeSize, frontier) {
  const size = parseTreeSize(treeSize);
  if (!Array.isArray(frontier) || frontier.length !== MERKLE_TREE_DEPTH) {
    throw treeError("INVALID_MERKLE_TREE_STATE", `frontier must contain exactly ${MERKLE_TREE_DEPTH} levels`);
  }
  return frontier.map((entry, level) => {
    const occupied = ((size >> BigInt(level)) & 1n) === 1n;
    if (!occupied) {
      if (entry !== null) throw treeError("INVALID_MERKLE_TREE_STATE", `frontier level ${level} must be empty for this tree size`);
      return null;
    }
    let normalized;
    try { normalized = normalizeFieldElement(String(entry ?? ""), `frontier[${level}]`); }
    catch (cause) { throw treeError("INVALID_MERKLE_TREE_STATE", cause.message); }
    return BigInt(normalized);
  });
}

/** Root of a tree described by (treeSize, frontier). */
export function merkleRootFromFrontier(treeSize, frontier) {
  const size = parseTreeSize(treeSize);
  const levels = parseMerkleFrontier(size, frontier);
  const zeros = merkleZeros();
  let hash = zeros[0];
  for (let level = 0; level < MERKLE_TREE_DEPTH; level += 1) {
    hash = levels[level] === null ? merkleNode(hash, zeros[level]) : merkleNode(levels[level], hash);
  }
  return hash;
}

export function emptyMerkleTreeState() {
  return {
    treeSize: 0,
    frontier: new Array(MERKLE_TREE_DEPTH).fill(null),
    root: merkleZeros()[MERKLE_TREE_DEPTH].toString(),
  };
}

/**
 * Appends leaves in order and returns the new (treeSize, frontier, root).
 * The input state is validated first, including that its root matches
 * `expectedRoot` when one is supplied.
 */
export function appendMerkleLeaves({ treeSize, frontier, expectedRoot = null }, leaves) {
  let size = parseTreeSize(treeSize);
  const levels = parseMerkleFrontier(size, frontier);
  if (expectedRoot !== null && merkleRootFromFrontier(size, frontier).toString() !== String(expectedRoot)) {
    throw treeError("MERKLE_FRONTIER_ROOT_MISMATCH", "stored frontier does not reproduce its Merkle root");
  }
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw treeError("INVALID_MERKLE_APPEND", "at least one leaf is required");
  }
  if (size + BigInt(leaves.length) > MAX_TREE_SIZE) {
    throw treeError("MERKLE_TREE_FULL", "the confidential note tree has no remaining capacity");
  }
  for (const leaf of leaves) {
    let carry = BigInt(normalizeFieldElement(String(leaf), "leaf"));
    let level = 0;
    while (((size >> BigInt(level)) & 1n) === 1n) {
      carry = merkleNode(levels[level], carry);
      levels[level] = null;
      level += 1;
    }
    levels[level] = carry;
    size += 1n;
  }
  const serialized = levels.map((entry) => (entry === null ? null : entry.toString()));
  return {
    treeSize: Number(size),
    frontier: serialized,
    root: merkleRootFromFrontier(size, serialized).toString(),
  };
}
