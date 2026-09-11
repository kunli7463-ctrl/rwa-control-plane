/*
 * Off-chain reference for circuits/confidential_ledger_v3.circom.
 * v3 differs from v2 only by two ownership constraints (audit finding H1):
 *   outputOwnerPubKey[0] === recipient
 *   outputOwnerPubKey[1] === inputOwnerPubKey[0]
 * Every hash, encoding and tree convention is inherited from reference_v2.js.
 */
const v2 = require("./reference_v2.js");

function buildJoinSplit(args) {
  const { inputs, outputs, recipient } = args;
  if (!Array.isArray(outputs) || outputs.length !== 2 || !Array.isArray(inputs) || inputs.length !== 2) {
    throw new Error("this circuit is a fixed 2-in / 2-out JoinSplit");
  }
  if (BigInt(outputs[0].ownerPubKey) !== BigInt(recipient)) {
    throw new Error("v3: output[0] must be owned by the public recipient key");
  }
  if (BigInt(outputs[1].ownerPubKey) !== BigInt(inputs[0].note.ownerPubKey)) {
    throw new Error("v3: change output[1] must return to the owner of input[0]");
  }
  return v2.buildJoinSplit(args);
}

module.exports = { ...v2, buildJoinSplit };
