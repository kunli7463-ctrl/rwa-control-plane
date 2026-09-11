import { createHash } from "node:crypto";

export const BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const JOIN_SPLIT_PUBLIC_SIGNAL_ORDER = Object.freeze([
  "merkleRoot", "contextId", "assetType", "fee", "recipient", "relayer", "transactionHash",
  "inputNullifier0", "inputNullifier1", "outputCommitmentX0", "outputCommitmentX1",
  "outputCommitmentY0", "outputCommitmentY1",
]);

function proofError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hash(value) {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalize(value)).digest("hex");
}

export function normalizeFieldElement(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw proofError("INVALID_PUBLIC_SIGNAL", `${label} must be a canonical decimal field element`);
  }
  const parsed = BigInt(value);
  if (parsed >= BN254_SCALAR_FIELD) throw proofError("INVALID_PUBLIC_SIGNAL", `${label} exceeds the BN254 scalar field`);
  return value;
}

export function normalizeJoinSplitPublicInputs(publicInputs, labelPrefix = "") {
  return Object.fromEntries(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => [
    name,
    normalizeFieldElement(String(publicInputs?.[name] ?? ""), `${labelPrefix}${name}`),
  ]));
}

export function joinSplitPublicInputsHash(publicInputs) {
  const normalized = normalizeJoinSplitPublicInputs(publicInputs);
  return hash(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.map((name) => normalized[name]));
}

export class SandboxNoProofAdapter {
  constructor() { this.mode = "SANDBOX_NO_ZK_PROOF"; }

  async verifyJoinSplit() {
    return { verified: false, mode: this.mode, productionAcceptable: false };
  }
}

export class Groth16JoinSplitProofAdapter {
  constructor({ verifier, verificationKey, manifest, expectedVerificationKeyHash, artifactManifestHash = null }) {
    if (!verifier || typeof verifier.verify !== "function") {
      throw proofError("PROOF_VERIFIER_REQUIRED", "Groth16 verifier implementation is required");
    }
    if (!manifest || manifest.protocol !== "groth16" || manifest.curve !== "bn128"
        || !manifest.circuitId || !manifest.circuitVersion) {
      throw proofError("INVALID_PROOF_MANIFEST", "versioned Groth16 circuit manifest is required");
    }
    if (canonicalize(manifest.publicSignalOrder) !== canonicalize(JOIN_SPLIT_PUBLIC_SIGNAL_ORDER)) {
      throw proofError("PUBLIC_SIGNAL_ORDER_MISMATCH", "manifest public signal order does not match the application contract");
    }
    const verificationKeyHash = hash(verificationKey);
    if (!expectedVerificationKeyHash || verificationKeyHash !== expectedVerificationKeyHash) {
      throw proofError("VERIFICATION_KEY_HASH_MISMATCH", "verification key is not the approved artifact");
    }
    this.verifier = verifier;
    this.verificationKey = structuredClone(verificationKey);
    this.manifest = structuredClone(manifest);
    if (artifactManifestHash !== null && !/^[0-9a-f]{64}$/.test(artifactManifestHash)) {
      throw proofError("INVALID_ARTIFACT_MANIFEST_HASH", "artifact manifest hash must be lowercase SHA-256");
    }
    this.manifestHash = artifactManifestHash ?? hash(manifest);
    this.verificationKeyHash = verificationKeyHash;
    this.mode = "GROTH16_VERIFIED";
  }

  async verifyJoinSplit({ proof, publicSignals, expectedPublicInputs }) {
    if (!proof || !Array.isArray(publicSignals) || publicSignals.length !== JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.length) {
      throw proofError("INVALID_PROOF_PACKAGE", "proof and exactly 13 public signals are required");
    }
    const normalized = publicSignals.map((value, index) => normalizeFieldElement(String(value), JOIN_SPLIT_PUBLIC_SIGNAL_ORDER[index]));
    for (let index = 0; index < JOIN_SPLIT_PUBLIC_SIGNAL_ORDER.length; index += 1) {
      const name = JOIN_SPLIT_PUBLIC_SIGNAL_ORDER[index];
      const expected = normalizeFieldElement(String(expectedPublicInputs?.[name]), `expected ${name}`);
      if (normalized[index] !== expected) {
        throw proofError("PROOF_CONTEXT_MISMATCH", `public signal ${name} does not match the authorized transaction context`);
      }
    }
    let verified;
    try { verified = await this.verifier.verify(this.verificationKey, normalized, proof); }
    catch (cause) {
      throw proofError("PROOF_VERIFIER_UNAVAILABLE", `Groth16 verifier failed: ${cause.message}`);
    }
    if (verified !== true) throw proofError("INVALID_ZERO_KNOWLEDGE_PROOF", "Groth16 proof verification failed");
    return {
      verified: true, mode: this.mode, circuitId: this.manifest.circuitId,
      circuitVersion: this.manifest.circuitVersion, verificationKeyHash: this.verificationKeyHash,
      manifestHash: this.manifestHash,
      proofHash: hash(proof), publicSignalsHash: hash(normalized),
    };
  }
}

export function verificationKeyHash(verificationKey) {
  return hash(verificationKey);
}
