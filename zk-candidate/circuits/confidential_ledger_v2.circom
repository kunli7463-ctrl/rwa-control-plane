pragma circom 2.1.6;

include "circomlib/circuits/pedersen.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/*
 * ============================================================================
 *  ConfidentialLedger v2 — fixed 2-in / 2-out JoinSplit
 * ============================================================================
 *
 *  Replaces confidential_ledger.circom (v1). v1's arithmetic layer was sound
 *  but it was a membership+nullifier proof with no value semantics, and its
 *  ownership model let whoever minted a note also spend it. This circuit is a
 *  real JoinSplit: two input notes are consumed, two output notes are created,
 *  and value is conserved.
 *
 *  FIXED SHAPE. Exactly 2 inputs and 2 outputs. There is no `enabled` flag, no
 *  optional slot and no amount==0 sentinel. Output[1] is the natural change
 *  note. A caller that wants to spend a single note must supply a second real
 *  note it owns; a caller that wants a single recipient sends the remainder to
 *  itself via output[1].
 *
 *  ---------------------------------------------------------------------------
 *  DOMAIN CONSTANTS (must be identical in scripts/reference_v2.js)
 *  ---------------------------------------------------------------------------
 *    NOTE_DOMAIN        0x434c324e4f544501   "CL2NOTE\x01"
 *    MERKLE_LEAF_DOMAIN 0x434c324c45414601   "CL2LEAF\x01"
 *    MERKLE_NODE_DOMAIN 0x434c324e4f444501   "CL2NODE\x01"
 *    NULLIFIER_DOMAIN   0x434c324e554c4c01   "CL2NULL\x01"
 *    TX_CONTEXT_DOMAIN  0x434c325458435401   "CL2TXCT\x01"
 *    OUTPUT_SET_DOMAIN  0x434c324f55545301   "CL2OUTS\x01"
 *  All six are distinct and non-zero.
 *
 *  ---------------------------------------------------------------------------
 *  NOTE COMMITMENT — Pedersen over 792 bits, byte aligned on purpose
 *  ---------------------------------------------------------------------------
 *    bit    [0,  63]  NOTE_DOMAIN   64 bits   ( 8 bytes)
 *    bit    [64, 127] amount        64 bits   ( 8 bytes)
 *    bit   [128, 159] assetType     32 bits   ( 4 bytes)
 *    bit   [160, 415] ownerPubKey  254 bits + 2 zero pad bits (32 bytes)
 *    bit   [416, 543] nonce        128 bits   (16 bytes)
 *    bit   [544, 791] blinding     248 bits   (31 bytes)
 *                                  ---------------------
 *                                  792 bits   (99 bytes)
 *
 *  Every field is byte aligned and little-endian, and Num2Bits emits LSB first,
 *  which is exactly what circomlib's Pedersen consumes. So the off-chain side
 *  can build one 99-byte little-endian buffer and hand it to
 *  circomlibjs.pedersenHash — no manual bit twiddling.
 *
 *  ownerPubKey is a full field element, so it uses Num2Bits_strict (254 bits +
 *  AliasCheck). Plain Num2Bits(254) would admit non-canonical bit strings that
 *  represent the same field element, i.e. two different commitments for one
 *  note. The two pad bits are constrained to zero.
 *
 *  circomlibjs.pedersenHash returns a COMPRESSED point. The off-chain reference
 *  MUST call babyJub.unpackPoint on it to recover (x, y); using the packed
 *  bytes as a coordinate silently produces a tree the circuit can never match.
 *
 *  ---------------------------------------------------------------------------
 *  HASH CHAINS
 *  ---------------------------------------------------------------------------
 *    ownerPubKey[i]        = Poseidon([ownerSecret[i]])
 *    commitment(x,y)       = Pedersen792(note)
 *    commitmentHash        = Poseidon([MERKLE_LEAF_DOMAIN, x, y])      <- leaf
 *    node(left,right)      = Poseidon([MERKLE_NODE_DOMAIN, left, right])
 *    emptyLeaf             = 0 ; zeros[k+1] = node(zeros[k], zeros[k])
 *    nullifierKey[i]       = Poseidon([NULLIFIER_DOMAIN, contextId, ownerSecret[i]])
 *    inputNullifier[i]     = Poseidon([nullifierKey[i], inputNonce[i],
 *                                      inputCommitmentHash[i]])
 *    outputSetHash         = Poseidon([OUTPUT_SET_DOMAIN, oX0, oY0, oX1, oY1])
 *    txCore                = Poseidon([TX_CONTEXT_DOMAIN, contextId, merkleRoot,
 *                                      assetType, fee, recipient])
 *    txMid                 = Poseidon([txCore, relayer, nf0, nf1])
 *    transactionHash       = Poseidon([txMid, outputSetHash])
 *
 *  ---------------------------------------------------------------------------
 *  PUBLIC SIGNAL ORDER (snarkjs publicSignals)
 *  ---------------------------------------------------------------------------
 *  There are no output signals; all 13 public values are public INPUTS, in
 *  declaration order:
 *      [0]  merkleRoot
 *      [1]  contextId
 *      [2]  assetType
 *      [3]  fee
 *      [4]  recipient
 *      [5]  relayer
 *      [6]  transactionHash
 *      [7]  inputNullifiers[0]
 *      [8]  inputNullifiers[1]
 *      [9]  outputCommitmentX[0]
 *      [10] outputCommitmentX[1]
 *      [11] outputCommitmentY[0]
 *      [12] outputCommitmentY[1]
 * ============================================================================
 */


/*
 * Pedersen note commitment over the 792-bit layout documented above.
 * NOTE_DOMAIN arrives as a template parameter so its bits are compile-time
 * constants folded into the R1CS (and therefore into the verification key).
 */
template NoteCommitment(NOTE_DOMAIN) {
    signal input amount;       // < 2^64
    signal input assetType;    // < 2^32
    signal input ownerPubKey;  // full field element
    signal input nonce;        // < 2^128
    signal input blinding;     // < 2^248

    signal output out[2];      // BabyJubjub point (x, y)

    component amountBits = Num2Bits(64);
    component assetBits  = Num2Bits(32);
    component pkBits     = Num2Bits_strict();   // 254 bits + AliasCheck
    component nonceBits  = Num2Bits(128);
    component blindBits  = Num2Bits(248);

    amountBits.in <== amount;
    assetBits.in  <== assetType;
    pkBits.in     <== ownerPubKey;
    nonceBits.in  <== nonce;
    blindBits.in  <== blinding;

    component ped = Pedersen(792);

    // [0, 63] domain tag — constant bits, LSB first
    for (var i = 0; i < 64; i++) {
        ped.in[i] <== (NOTE_DOMAIN >> i) & 1;
    }
    // [64, 127] amount
    for (var i = 0; i < 64; i++) {
        ped.in[64 + i] <== amountBits.out[i];
    }
    // [128, 159] assetType
    for (var i = 0; i < 32; i++) {
        ped.in[128 + i] <== assetBits.out[i];
    }
    // [160, 413] ownerPubKey, [414, 415] zero padding to a 32-byte field
    for (var i = 0; i < 254; i++) {
        ped.in[160 + i] <== pkBits.out[i];
    }
    ped.in[414] <== 0;
    ped.in[415] <== 0;
    // [416, 543] nonce
    for (var i = 0; i < 128; i++) {
        ped.in[416 + i] <== nonceBits.out[i];
    }
    // [544, 791] blinding
    for (var i = 0; i < 248; i++) {
        ped.in[544 + i] <== blindBits.out[i];
    }

    out[0] <== ped.out[0];
    out[1] <== ped.out[1];
}


/*
 * Merkle inclusion for one leaf. Returns the reconstructed root.
 *
 * direction = 0 -> the current node is the LEFT child, sibling on the right
 * direction = 1 -> the current node is the RIGHT child, sibling on the left
 *
 * Both selector expressions are degree 2, so each costs one R1CS constraint.
 * The booleanity constraint is what makes them a selector rather than an
 * arbitrary linear combination; without it a prover can steer the fold to any
 * target root and forge membership.
 */
template MerklePath(DEPTH, NODE_DOMAIN) {
    signal input leaf;
    signal input pathElements[DEPTH];
    signal input pathDirections[DEPTH];
    signal output root;

    signal level[DEPTH + 1];
    signal left[DEPTH];
    signal right[DEPTH];
    component nodeHashers[DEPTH];

    level[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        pathDirections[i] * (pathDirections[i] - 1) === 0;

        left[i]  <== level[i]        + pathDirections[i] * (pathElements[i] - level[i]);
        right[i] <== pathElements[i] + pathDirections[i] * (level[i] - pathElements[i]);

        nodeHashers[i] = Poseidon(3);
        nodeHashers[i].inputs[0] <== NODE_DOMAIN;
        nodeHashers[i].inputs[1] <== left[i];
        nodeHashers[i].inputs[2] <== right[i];

        level[i + 1] <== nodeHashers[i].out;
    }

    root <== level[DEPTH];
}


template ConfidentialLedgerJoinSplit(TREE_DEPTH) {

    var NOTE_DOMAIN        = 0x434c324e4f544501; // "CL2NOTE\x01"
    var MERKLE_LEAF_DOMAIN = 0x434c324c45414601; // "CL2LEAF\x01"
    var MERKLE_NODE_DOMAIN = 0x434c324e4f444501; // "CL2NODE\x01"
    var NULLIFIER_DOMAIN   = 0x434c324e554c4c01; // "CL2NULL\x01"
    var TX_CONTEXT_DOMAIN  = 0x434c325458435401; // "CL2TXCT\x01"
    var OUTPUT_SET_DOMAIN  = 0x434c324f55545301; // "CL2OUTS\x01"

    assert(TREE_DEPTH > 0);
    assert(TREE_DEPTH <= 64);

    // =====================================================================
    // Public inputs
    // =====================================================================
    signal input merkleRoot;
    signal input contextId;
    signal input assetType;
    signal input fee;
    signal input recipient;
    signal input relayer;
    signal input transactionHash;
    signal input inputNullifiers[2];
    signal input outputCommitmentX[2];
    signal input outputCommitmentY[2];

    // =====================================================================
    // Private witness — input notes
    // =====================================================================
    signal input inputAmount[2];
    signal input inputOwnerPubKey[2];
    signal input inputOwnerSecret[2];
    signal input inputNonce[2];
    signal input inputBlinding[2];
    signal input pathElements[2][TREE_DEPTH];
    signal input pathDirections[2][TREE_DEPTH];

    // =====================================================================
    // Private witness — output notes
    // =====================================================================
    signal input outputAmount[2];
    signal input outputOwnerPubKey[2];
    signal input outputNonce[2];
    signal input outputBlinding[2];

    // =====================================================================
    // 1. Public scalar range binding
    // ---------------------------------------------------------------------
    // assetType and fee are public, but a public input is still prover-chosen
    // until something constrains it. Range-binding them gives each a unique
    // canonical encoding and, for fee, keeps the value-conservation sum far
    // below the field modulus.
    // =====================================================================
    component assetTypeBits = Num2Bits(32);
    assetTypeBits.in <== assetType;

    component feeBits = Num2Bits(64);
    feeBits.in <== fee;

    // =====================================================================
    // 2. Ownership: pubkey is derived from the secret, and only the pubkey
    //    goes into the note.
    // ---------------------------------------------------------------------
    // This is the fix for v1's central defect. In v1 the note commitment took
    // ownerSecret directly, so the party that built the note held the full
    // opening and could spend it, or pre-compute its nullifier and burn it.
    // Here a sender needs only the recipient's outputOwnerPubKey.
    // =====================================================================
    component ownerPk[2];
    for (var i = 0; i < 2; i++) {
        ownerPk[i] = Poseidon(1);
        ownerPk[i].inputs[0] <== inputOwnerSecret[i];
        inputOwnerPubKey[i] === ownerPk[i].out;
    }

    // =====================================================================
    // 3. Input notes: commitment -> leaf -> Merkle root
    // ---------------------------------------------------------------------
    // Both inputs must live under the SAME public merkleRoot. Each carries its
    // own independent path, so they may sit anywhere in the tree.
    // =====================================================================
    component inputNote[2];
    component inputLeaf[2];
    component inputPath[2];

    signal inputCommitmentHash[2];

    for (var i = 0; i < 2; i++) {
        inputNote[i] = NoteCommitment(NOTE_DOMAIN);
        inputNote[i].amount      <== inputAmount[i];
        inputNote[i].assetType   <== assetType;          // all notes share the public type
        inputNote[i].ownerPubKey <== inputOwnerPubKey[i];
        inputNote[i].nonce       <== inputNonce[i];
        inputNote[i].blinding    <== inputBlinding[i];

        inputLeaf[i] = Poseidon(3);
        inputLeaf[i].inputs[0] <== MERKLE_LEAF_DOMAIN;
        inputLeaf[i].inputs[1] <== inputNote[i].out[0];
        inputLeaf[i].inputs[2] <== inputNote[i].out[1];

        inputCommitmentHash[i] <== inputLeaf[i].out;

        inputPath[i] = MerklePath(TREE_DEPTH, MERKLE_NODE_DOMAIN);
        inputPath[i].leaf <== inputCommitmentHash[i];
        for (var d = 0; d < TREE_DEPTH; d++) {
            inputPath[i].pathElements[d]   <== pathElements[i][d];
            inputPath[i].pathDirections[d] <== pathDirections[i][d];
        }

        inputPath[i].root === merkleRoot;
    }

    // =====================================================================
    // 4. Nullifiers
    // ---------------------------------------------------------------------
    // nullifierKey binds NULLIFIER_DOMAIN and contextId, so the same note
    // produces a different tag on a different chain / ledger / contract /
    // version — no cross-deployment collision and no cross-ledger linkability.
    // The tag is deterministic in the note, so it cannot be re-randomised to
    // double spend; and it contains ownerSecret, so nobody but the owner can
    // pre-compute it.
    //
    // It deliberately does NOT depend on recipient / relayer / fee: if it did,
    // the same note would yield different tags under different transactions and
    // the settlement layer's spent-set would stop preventing double spends.
    // =====================================================================
    component nullifierKey[2];
    component nullifierHash[2];

    for (var i = 0; i < 2; i++) {
        nullifierKey[i] = Poseidon(3);
        nullifierKey[i].inputs[0] <== NULLIFIER_DOMAIN;
        nullifierKey[i].inputs[1] <== contextId;
        nullifierKey[i].inputs[2] <== inputOwnerSecret[i];

        nullifierHash[i] = Poseidon(3);
        nullifierHash[i].inputs[0] <== nullifierKey[i].out;
        nullifierHash[i].inputs[1] <== inputNonce[i];
        nullifierHash[i].inputs[2] <== inputCommitmentHash[i];

        inputNullifiers[i] === nullifierHash[i].out;
    }

    /*
     * The two inputs must be distinct notes. Without this a prover could pass
     * the SAME note in both slots and mint outputs worth twice its value while
     * the contract only ever sees one nullifier to mark.
     *
     * IsEqual comes from circomlib comparators.circom and is built on IsZero,
     * whose soundness comes from the constraint pair
     *     in * inv === 1 - out ,  in * out === 0
     * The inverse is only a witness hint; there is no raw division and no
     * unconstrained signal here.
     */
    component nullifiersEqual = IsEqual();
    nullifiersEqual.in[0] <== inputNullifiers[0];
    nullifiersEqual.in[1] <== inputNullifiers[1];
    nullifiersEqual.out === 0;

    // =====================================================================
    // 5. Output notes
    // ---------------------------------------------------------------------
    // Both outputs carry the same public assetType, so a JoinSplit cannot be
    // used to transmute one asset into another.
    // =====================================================================
    component outputNote[2];

    for (var i = 0; i < 2; i++) {
        outputNote[i] = NoteCommitment(NOTE_DOMAIN);
        outputNote[i].amount      <== outputAmount[i];
        outputNote[i].assetType   <== assetType;
        outputNote[i].ownerPubKey <== outputOwnerPubKey[i];
        outputNote[i].nonce       <== outputNonce[i];
        outputNote[i].blinding    <== outputBlinding[i];

        outputCommitmentX[i] === outputNote[i].out[0];
        outputCommitmentY[i] === outputNote[i].out[1];
    }

    // =====================================================================
    // 6. Value conservation
    // ---------------------------------------------------------------------
    // Each amount is range-bound to 64 bits inside NoteCommitment, and fee is
    // range-bound above, so the largest reachable side of this equation is
    // 3 * (2^64 - 1) < 2^66, far below p_BN254 (~2^254). No modular wrap can
    // fake a balanced transaction.
    // =====================================================================
    inputAmount[0] + inputAmount[1] === outputAmount[0] + outputAmount[1] + fee;

    // =====================================================================
    // 7. Transaction-context binding
    // ---------------------------------------------------------------------
    // Layered Poseidon with a fixed, documented input order. Every field that
    // the settlement layer acts on is inside this hash, so lifting the proof
    // out of the mempool and re-submitting it with a different recipient,
    // relayer, fee, context or output set makes verification fail.
    // =====================================================================
    component outputSetHash = Poseidon(5);
    outputSetHash.inputs[0] <== OUTPUT_SET_DOMAIN;
    outputSetHash.inputs[1] <== outputCommitmentX[0];
    outputSetHash.inputs[2] <== outputCommitmentY[0];
    outputSetHash.inputs[3] <== outputCommitmentX[1];
    outputSetHash.inputs[4] <== outputCommitmentY[1];

    component txCore = Poseidon(6);
    txCore.inputs[0] <== TX_CONTEXT_DOMAIN;
    txCore.inputs[1] <== contextId;
    txCore.inputs[2] <== merkleRoot;
    txCore.inputs[3] <== assetType;
    txCore.inputs[4] <== fee;
    txCore.inputs[5] <== recipient;

    component txMid = Poseidon(4);
    txMid.inputs[0] <== txCore.out;
    txMid.inputs[1] <== relayer;
    txMid.inputs[2] <== inputNullifiers[0];
    txMid.inputs[3] <== inputNullifiers[1];

    component txFinal = Poseidon(2);
    txFinal.inputs[0] <== txMid.out;
    txFinal.inputs[1] <== outputSetHash.out;

    transactionHash === txFinal.out;
}

component main {
    public [
        merkleRoot,
        contextId,
        assetType,
        fee,
        recipient,
        relayer,
        transactionHash,
        inputNullifiers,
        outputCommitmentX,
        outputCommitmentY
    ]
} = ConfidentialLedgerJoinSplit(32);
