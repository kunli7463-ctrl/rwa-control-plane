/*
 * Off-chain reference implementation for circuits/confidential_ledger_v2.circom
 * (fixed 2-in / 2-out JoinSplit).
 *
 * Every constant, input order, field encoding and tree convention here MUST
 * match the circuit exactly. scripts/run_tests_v2.js proves that it does by
 * comparing against the actual witness signal by signal.
 *
 * circomlib 2.0.5 / circomlibjs 0.1.7 / BN254 / BabyJubjub.
 */
const { buildPedersenHash, buildBabyjub, buildPoseidon } = require("circomlibjs");

// ---------------------------------------------------------------------------
// Domain constants — identical to the `var` declarations in the circuit.
// ---------------------------------------------------------------------------
const NOTE_DOMAIN        = 0x434c324e4f544501n; // "CL2NOTE\x01"
const MERKLE_LEAF_DOMAIN = 0x434c324c45414601n; // "CL2LEAF\x01"
const MERKLE_NODE_DOMAIN = 0x434c324e4f444501n; // "CL2NODE\x01"
const NULLIFIER_DOMAIN   = 0x434c324e554c4c01n; // "CL2NULL\x01"
const TX_CONTEXT_DOMAIN  = 0x434c325458435401n; // "CL2TXCT\x01"
const OUTPUT_SET_DOMAIN  = 0x434c324f55545301n; // "CL2OUTS\x01"

const TREE_DEPTH = 32;
const EMPTY_LEAF = 0n;

let _pedersen, _babyjub, _poseidon, F;

async function init() {
  if (_poseidon) return;
  _pedersen = await buildPedersenHash();
  _babyjub = await buildBabyjub();
  _poseidon = await buildPoseidon();
  F = _poseidon.F;
}

/** Poseidon over BN254, returning a bigint. */
const H = (xs) => F.toObject(_poseidon(xs.map((x) => F.e(x))));

// ---------------------------------------------------------------------------
// Field encoding
// ---------------------------------------------------------------------------

/** Little-endian fixed-width byte encoding, matching Num2Bits' LSB-first order. */
function leBytes(v, nBytes) {
  let x = BigInt(v);
  if (x < 0n) throw new Error("negative value");
  if (x >= 1n << BigInt(8 * nBytes)) throw new Error(`value does not fit in ${nBytes} bytes`);
  const b = Buffer.alloc(nBytes);
  for (let i = 0; i < nBytes; i++) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
}

const RANGE_BITS = {
  amount: 64n, assetType: 32n, nonce: 128n, blinding: 248n, fee: 64n,
};

function assertRange(name, value) {
  const bits = RANGE_BITS[name];
  if (bits === undefined) return;
  const v = BigInt(value);
  if (v < 0n || v >= 1n << bits) {
    throw new Error(`${name}=${v} is outside its ${bits}-bit range; the circuit would reject it`);
  }
}

// ---------------------------------------------------------------------------
// Note commitment — Pedersen over the 792-bit / 99-byte layout
//
//   [0,63]    NOTE_DOMAIN    8 bytes
//   [64,127]  amount         8 bytes
//   [128,159] assetType      4 bytes
//   [160,415] ownerPubKey   32 bytes  (254 bits + 2 zero pad bits)
//   [416,543] nonce         16 bytes
//   [544,791] blinding      31 bytes
// ---------------------------------------------------------------------------
function noteMessage(note) {
  assertRange("amount", note.amount);
  assertRange("assetType", note.assetType);
  assertRange("nonce", note.nonce);
  assertRange("blinding", note.blinding);
  return Buffer.concat([
    leBytes(NOTE_DOMAIN, 8),
    leBytes(note.amount, 8),
    leBytes(note.assetType, 4),
    leBytes(note.ownerPubKey, 32), // top 2 bits are zero because pk < p < 2^254
    leBytes(note.nonce, 16),
    leBytes(note.blinding, 31),
  ]);
}

/**
 * Returns the note commitment as [x, y].
 *
 * circomlibjs' pedersenHash returns a COMPRESSED BabyJubjub point (32 bytes).
 * The circuit exposes the uncompressed coordinates, so the packed value must be
 * run through babyJub.unpackPoint. Skipping this step is the classic
 * integration bug: it produces a tree the circuit can never match, and the
 * failure only shows up as "witness generation failed" much later.
 */
function noteCommitment(note) {
  const msg = noteMessage(note);
  if (msg.length !== 99) throw new Error(`note message must be 99 bytes, got ${msg.length}`);
  const packed = _pedersen.hash(msg);
  const point = _babyjub.unpackPoint(packed);
  if (point === null) throw new Error("babyJub.unpackPoint failed — packed point is not on the curve");
  return [_babyjub.F.toObject(point[0]), _babyjub.F.toObject(point[1])];
}

/**
 * The RAW packed output of circomlibjs.pedersenHash, as a bigint.
 * Exposed only so the test suite can demonstrate what goes wrong when an
 * integrator uses it as a coordinate. Never use this to build a tree.
 */
function packedCommitment(note) {
  const packed = _pedersen.hash(noteMessage(note));
  let v = 0n;
  for (let i = packed.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(packed[i]);
  return v;
}

// ---------------------------------------------------------------------------
// Hash chains
// ---------------------------------------------------------------------------
const ownerPubKey = (ownerSecret) => H([ownerSecret]);

/** Merkle leaf == "commitment hash". */
function commitmentHash(note) {
  const [x, y] = noteCommitment(note);
  return H([MERKLE_LEAF_DOMAIN, x, y]);
}

const merkleNode = (l, r) => H([MERKLE_NODE_DOMAIN, l, r]);

const nullifierKey = (contextId, ownerSecret) =>
  H([NULLIFIER_DOMAIN, contextId, ownerSecret]);

const inputNullifier = (note, ownerSecret, contextId) =>
  H([nullifierKey(contextId, ownerSecret), note.nonce, commitmentHash(note)]);

const outputSetHash = (o0, o1) =>
  H([OUTPUT_SET_DOMAIN, o0[0], o0[1], o1[0], o1[1]]);

function transactionHash({ contextId, merkleRoot, assetType, fee, recipient, relayer,
                           nullifiers, outCommitments }) {
  const txCore = H([TX_CONTEXT_DOMAIN, contextId, merkleRoot, assetType, fee, recipient]);
  const txMid = H([txCore, relayer, nullifiers[0], nullifiers[1]]);
  return H([txMid, outputSetHash(outCommitments[0], outCommitments[1])]);
}

/** Helper for building a deployment-pinned contextId. Shape is protocol policy;
 *  the circuit treats contextId as an opaque public field element. */
const makeContextId = ({ protocolId, ledgerId, chainId, contractAddress, version }) =>
  H([protocolId, ledgerId, chainId, contractAddress, version]);

// ---------------------------------------------------------------------------
// Fixed-depth Merkle tree
//
// The circuit does not fix the empty-leaf constant, so it is pinned here and
// must match the on-chain incremental tree exactly.
// ---------------------------------------------------------------------------
function buildTree(leaves, depth = TREE_DEPTH) {
  const zeros = [EMPTY_LEAF];
  for (let i = 1; i <= depth; i++) zeros.push(merkleNode(zeros[i - 1], zeros[i - 1]));
  const layers = [];
  let layer = leaves.slice();
  for (let d = 0; d < depth; d++) {
    layers.push(layer);
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(merkleNode(layer[i], i + 1 < layer.length ? layer[i + 1] : zeros[d]));
    }
    layer = next.length ? next : [zeros[d + 1]];
  }
  layers.push(layer);
  return { layers, zeros, depth, root: layer.length ? layer[0] : zeros[depth] };
}

function merkleProof(tree, index) {
  const pathElements = [], pathDirections = [];
  let idx = index;
  for (let d = 0; d < tree.depth; d++) {
    const layer = tree.layers[d];
    pathElements.push((idx ^ 1) < layer.length ? layer[idx ^ 1] : tree.zeros[d]);
    pathDirections.push(BigInt(idx & 1)); // 1 => current node is the RIGHT child
    idx >>= 1;
  }
  return { pathElements, pathDirections };
}

// ---------------------------------------------------------------------------
// Transaction assembly
// ---------------------------------------------------------------------------

/**
 * inputs:  [{ note, ownerSecret, index }, ...] length 2
 * outputs: [note, note]   (note.ownerPubKey is the RECIPIENT's public key;
 *                          the sender never needs the recipient's secret)
 */
function buildJoinSplit({ inputs, outputs, tree, contextId, assetType, fee, recipient, relayer }) {
  if (inputs.length !== 2 || outputs.length !== 2) {
    throw new Error("this circuit is a fixed 2-in / 2-out JoinSplit");
  }
  assertRange("fee", fee);
  assertRange("assetType", assetType);

  const sumIn = BigInt(inputs[0].note.amount) + BigInt(inputs[1].note.amount);
  const sumOut = BigInt(outputs[0].amount) + BigInt(outputs[1].amount) + BigInt(fee);
  if (sumIn !== sumOut) {
    throw new Error(`value not conserved: in=${sumIn} out+fee=${sumOut}`);
  }
  for (const n of [inputs[0].note, inputs[1].note, outputs[0], outputs[1]]) {
    if (BigInt(n.assetType) !== BigInt(assetType)) {
      throw new Error("every note must carry the transaction's public assetType");
    }
  }

  const nullifiers = inputs.map((i) => inputNullifier(i.note, i.ownerSecret, contextId));
  if (nullifiers[0] === nullifiers[1]) {
    throw new Error("the two input notes must be distinct; the circuit rejects equal nullifiers");
  }

  const outCommitments = outputs.map(noteCommitment);
  const proofs = inputs.map((i) => merkleProof(tree, i.index));

  const txHash = transactionHash({
    contextId, merkleRoot: tree.root, assetType, fee, recipient, relayer,
    nullifiers, outCommitments,
  });

  return {
    input: {
      // public
      merkleRoot: tree.root.toString(),
      contextId: contextId.toString(),
      assetType: assetType.toString(),
      fee: fee.toString(),
      recipient: recipient.toString(),
      relayer: relayer.toString(),
      transactionHash: txHash.toString(),
      inputNullifiers: nullifiers.map(String),
      outputCommitmentX: outCommitments.map((c) => c[0].toString()),
      outputCommitmentY: outCommitments.map((c) => c[1].toString()),
      // private, inputs
      inputAmount: inputs.map((i) => i.note.amount.toString()),
      inputOwnerPubKey: inputs.map((i) => i.note.ownerPubKey.toString()),
      inputOwnerSecret: inputs.map((i) => i.ownerSecret.toString()),
      inputNonce: inputs.map((i) => i.note.nonce.toString()),
      inputBlinding: inputs.map((i) => i.note.blinding.toString()),
      pathElements: proofs.map((p) => p.pathElements.map(String)),
      pathDirections: proofs.map((p) => p.pathDirections.map(String)),
      // private, outputs
      outputAmount: outputs.map((o) => o.amount.toString()),
      outputOwnerPubKey: outputs.map((o) => o.ownerPubKey.toString()),
      outputNonce: outputs.map((o) => o.nonce.toString()),
      outputBlinding: outputs.map((o) => o.blinding.toString()),
    },
    derived: { nullifiers, outCommitments, txHash, root: tree.root },
  };
}

/** Build a note the way a SENDER does: from the recipient's public key only. */
const makeNote = ({ amount, assetType, ownerPubKey, nonce, blinding }) =>
  ({ amount, assetType, ownerPubKey, nonce, blinding });

module.exports = {
  init, H, leBytes, noteMessage, noteCommitment, commitmentHash, merkleNode,
  ownerPubKey, nullifierKey, inputNullifier, outputSetHash, transactionHash,
  makeContextId, buildTree, merkleProof, buildJoinSplit, makeNote, assertRange,
  packedCommitment,
  NOTE_DOMAIN, MERKLE_LEAF_DOMAIN, MERKLE_NODE_DOMAIN, NULLIFIER_DOMAIN,
  TX_CONTEXT_DOMAIN, OUTPUT_SET_DOMAIN, EMPTY_LEAF, TREE_DEPTH,
};
