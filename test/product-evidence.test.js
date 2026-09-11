import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  PRODUCT_EVIDENCE_ALGORITHM,
  PRODUCT_EVIDENCE_ENVELOPE,
  productEvidencePayloadHash,
  signProductEvidence,
  verifyProductEvidenceSignature,
} from "../src/security/product-evidence.js";

function fields() {
  return {
    tenantId: "tenant-hk-01",
    productId: "product-hk-01",
    id: "evidence-legal-01",
    requirementCode: "legal_opinion",
    sourceInstitutionId: "issuer-hk-01",
    schemaVersion: "1.0",
    contentHash: "a".repeat(64),
    issuedAt: "2026-09-01T00:00:00.000Z",
    expiresAt: "2026-12-01T00:00:00.000Z",
    keyId: "primary-v1",
  };
}

test("product evidence signature binds every canonical context field", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signed = signProductEvidence(fields(), privateKey);
  assert.equal(signed.envelopeVersion, PRODUCT_EVIDENCE_ENVELOPE);
  assert.equal(signed.signatureAlgorithm, PRODUCT_EVIDENCE_ALGORITHM);
  const result = verifyProductEvidenceSignature(signed, publicKey);
  assert.match(result.payloadHash, /^[0-9a-f]{64}$/);
  assert.equal(result.payloadHash, productEvidencePayloadHash(signed));

  for (const mutation of [
    { tenantId: "tenant-hk-02" },
    { productId: "product-hk-02" },
    { id: "evidence-legal-02" },
    { requirementCode: "offering_document" },
    { sourceInstitutionId: "issuer-hk-02" },
    { schemaVersion: "2.0" },
    { contentHash: "b".repeat(64) },
    { issuedAt: "2026-09-01T00:00:01.000Z" },
    { expiresAt: "2026-12-01T00:00:01.000Z" },
    { keyId: "rotated-v2" },
  ]) {
    assert.throws(
      () => verifyProductEvidenceSignature({ ...signed, ...mutation }, publicKey),
      { code: "INVALID_EVIDENCE_SIGNATURE" },
    );
  }
});

test("product evidence rejects the wrong key and non-canonical signature encoding", () => {
  const signer = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const signed = signProductEvidence(fields(), signer.privateKey);
  assert.throws(
    () => verifyProductEvidenceSignature(signed, other.publicKey),
    { code: "INVALID_EVIDENCE_SIGNATURE" },
  );
  assert.throws(
    () => verifyProductEvidenceSignature({ ...signed, signature: "not-base64!!!!!!!!" }, signer.publicKey),
    { code: "INVALID_EVIDENCE_SIGNATURE_ENCODING" },
  );
});
