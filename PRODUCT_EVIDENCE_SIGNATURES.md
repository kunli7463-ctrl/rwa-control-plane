# Product activation evidence signature contract

Product activation evidence uses an institution-controlled Ed25519 signing key.
The service never signs evidence on behalf of an institution and never accepts a
signature as an opaque metadata string.

## Versioned canonical payload

The exact signed object is canonical JSON with recursively sorted object keys:

```json
{
  "contentHash": "<lowercase SHA-256>",
  "documentSchemaVersion": "1.0",
  "envelope": "rwa.product-activation-evidence.v1",
  "evidenceId": "evidence-001",
  "expiresAt": "2026-12-01T00:00:00.000Z",
  "issuedAt": "2026-09-01T00:00:00.000Z",
  "productId": "product-001",
  "requirementCode": "legal_opinion",
  "signatureAlgorithm": "Ed25519",
  "signingKeyId": "primary-v1",
  "sourceInstitutionId": "issuer-001",
  "tenantId": "tenant-001"
}
```

Dates are normalized with JavaScript `Date#toISOString()`. The signature is
Ed25519 over the UTF-8 canonical JSON bytes and is transported as canonical
Base64. `src/security/product-evidence.js` is the normative implementation.

## Verification boundary

Before evidence can become `SATISFIED`, the service verifies all of the following:

- the envelope and algorithm are exactly the supported version;
- tenant, product, evidence ID, requirement, source institution and document
  hash are all covered by the signature;
- the source institution is active, approved and assigned to the responsible
  product role;
- the selected signing key is registered, active, Ed25519, not revoked and was
  valid at `issuedAt`;
- the evidence is not expired, is not too far in the future and does not exceed
  the maximum validity policy;
- the signature verifies against the registered public key.

The database records the key ID, algorithm, canonical payload hash, verifier
version, verification result and verification time. Raw private keys are never
accepted by this service.

## Key lifecycle

An institution receives `primary-v1` when its approved Ed25519 public key is
registered. Additional keys can be registered before rotation:

```text
POST /api/catalog/institutions/{institutionId}/signing-keys
```

Body fields: `keyId`, `algorithm`, `publicKeyPem`, `validFrom`, and optional
`validUntil`.

Revoke a compromised key with:

```text
POST /api/catalog/institutions/{institutionId}/signing-keys/{keyId}/revoke
```

Body: `{ "reason": "..." }`.

Key identity and public material are immutable. Retired or revoked keys cannot
be reactivated. Revocation invalidates requirements backed by that key and
pauses any active product that no longer has all mandatory verified evidence.

## External responsibility

The institution must protect the corresponding private key, approve the
canonical payload before signing, and operate its real-world authorization,
HSM/KMS, revocation and audit process. This software verifies the cryptographic
statement; it does not independently prove that the underlying document or
asset fact is legally true.
