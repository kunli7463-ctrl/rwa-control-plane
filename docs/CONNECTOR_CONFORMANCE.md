# Institution connector conformance contract

The first production connector boundary is the signed callback schema
`rwa.institution-callback.v1`. It covers legal register, cash and custody facts.
Partners can validate an envelope before integration with PostgreSQL:

```sh
npm run connector:verify-callback -- callback.json institution-ed25519-public.pem
```

The repository also provides `sdk/institution-connector.js`. It constructs the
canonical envelope, calculates the payload hash, signs with the institution's
Ed25519 key and submits to `POST /api/institution-callbacks` with the callback ID
as the idempotency key. Production endpoints must use HTTPS; only an explicit
local-development option permits loopback HTTP. The HTTP endpoint is machine
authenticated by the signed envelope and therefore does not use a browser
session or CSRF token.

A conformant callback must satisfy all of the following:

- Ed25519 signature over the canonical JSON envelope excluding `signature`,
  made with the key named by the signed `keyId` field (omitted means
  `primary-v1`). The key must be `ACTIVE`, unrevoked and inside its validity
  window in the governed `institution_signing_keys` registry — revoking a key
  through the catalog immediately stops callbacks signed with it;
- one active tenant, institution, product and monotonic channel sequence;
- `occurredAt < expiresAt`, bounded validity and clock skew;
- SHA-256 payload hash and exact event type `<CHANNEL>.<OUTCOME>`;
- `REGISTER` and `CASH` subjects are transactions; `CUSTODY` subjects are positions;
- decimal amounts and units are canonical non-negative integer strings;
- channel-specific details contain no additional fields.

Channel contracts:

| Channel | Required institutional role | Required details |
|---|---|---|
| REGISTER | `transfer_agent` | `registerReference`, `assetCode`, `units`, `registerVersion` |
| CASH | `cash_provider` | `bankReference`, `currency`, `amountMinor`, `feeMinor` |
| CUSTODY | `custodian` | `statementId`, `assetCode`, `balanceUnits`, `asOf` |

Passing the standalone validator proves schema, payload hash, time window and
signature conformance only. The server still checks active institution status,
product-role assignment, tenant scope, stream ordering, transaction context and
economic commitments inside a Serializable transaction. Buffered
out-of-order callbacks are re-authorized (institution, role, signing key) when
their turn comes; if that authority was withdrawn in the meantime the stream
stops at that sequence and a CRITICAL `BUFFERED_CALLBACK_*` incident is opened
instead of applying a pre-positioned callback. Tenant mismatch, unknown or
inactive institution, missing role assignment, unknown or revoked key and a bad
signature all return the same `401 CALLBACK_AUTHENTICATION_FAILED`, so an
unauthenticated caller cannot enumerate institutions, roles or key IDs; use the
standalone validator to diagnose signature problems. A callback is never
allowed to silently rewrite a settled transaction; mismatch or failure creates
an external incident and requires a separate maker/checker remediation workflow.

NAV, identity, authoritative Merkle-root publication and legal-register bridge
contracts remain institution-specific. They must be added as versioned schemas
with the same fail-closed, signed, ordered and idempotent properties rather than
being represented as untyped webhooks.
