import { createHash, createPublicKey, sign, verify } from "node:crypto";

export const PRODUCT_EVIDENCE_ENVELOPE = "rwa.product-activation-evidence.v1";
export const PRODUCT_EVIDENCE_ALGORITHM = "Ed25519";
export const PRODUCT_EVIDENCE_VERIFIER = "product-evidence-verifier.v1";

function evidenceError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function canonicalizeProductEvidence(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeProductEvidence).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalizeProductEvidence(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function productEvidencePayload({
  tenantId, productId, id, requirementCode, sourceInstitutionId, schemaVersion,
  contentHash, issuedAt, expiresAt, keyId,
}) {
  return {
    envelope: PRODUCT_EVIDENCE_ENVELOPE,
    tenantId,
    productId,
    evidenceId: id,
    requirementCode,
    sourceInstitutionId,
    documentSchemaVersion: schemaVersion,
    contentHash,
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    signatureAlgorithm: PRODUCT_EVIDENCE_ALGORITHM,
    signingKeyId: keyId,
  };
}

export function productEvidencePayloadHash(fields) {
  return createHash("sha256")
    .update(canonicalizeProductEvidence(productEvidencePayload(fields)))
    .digest("hex");
}

function strictBase64(value) {
  if (typeof value !== "string" || value.length < 4 || value.length > 16_384
      || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw evidenceError("INVALID_EVIDENCE_SIGNATURE_ENCODING", "evidence signature must be canonical base64");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw evidenceError("INVALID_EVIDENCE_SIGNATURE_ENCODING", "evidence signature must be canonical base64");
  }
  return decoded;
}

export function assertEd25519PublicKey(publicKeyPem) {
  let key;
  try {
    key = publicKeyPem?.type === "public" ? publicKeyPem : createPublicKey(publicKeyPem);
  } catch {
    throw evidenceError("INVALID_INSTITUTION_SIGNING_KEY", "institution signing key is not valid public-key material");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw evidenceError("UNSUPPORTED_EVIDENCE_SIGNING_KEY", "product evidence requires an Ed25519 public key");
  }
  return key;
}

export function verifyProductEvidenceSignature(fields, publicKeyPem) {
  const key = assertEd25519PublicKey(publicKeyPem);
  const signature = strictBase64(fields.signature);
  const payload = productEvidencePayload(fields);
  let valid = false;
  try {
    valid = verify(null, Buffer.from(canonicalizeProductEvidence(payload)), key, signature);
  } catch {
    valid = false;
  }
  if (!valid) throw evidenceError("INVALID_EVIDENCE_SIGNATURE", "product activation evidence signature is invalid");
  return {
    payload,
    payloadHash: createHash("sha256").update(canonicalizeProductEvidence(payload)).digest("hex"),
    verifierVersion: PRODUCT_EVIDENCE_VERIFIER,
  };
}

export function signProductEvidence(fields, privateKey) {
  const payload = productEvidencePayload(fields);
  return {
    ...fields,
    envelopeVersion: PRODUCT_EVIDENCE_ENVELOPE,
    signatureAlgorithm: PRODUCT_EVIDENCE_ALGORITHM,
    signature: sign(
      null,
      Buffer.from(canonicalizeProductEvidence(payload)),
      privateKey,
    ).toString("base64"),
  };
}
