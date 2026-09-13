# Architecture review remediation — 2026-09-11

## Scope and current decision

This remediation addresses the findings of the 2026-09-11 architecture and
security review of the control plane (confidential JoinSplit settlement,
PostgreSQL guards, prover and Outbox workers, callbacks, OIDC and disclosure).
It does not authorize real-asset use. External KMS, OIDC/IGA, institution
connectors, an audited circuit with a production ceremony, deployment controls
and legal approval remain deployment prerequisites.

## Findings fixed

| ID | Finding | Change | Migration |
|----|---------|--------|-----------|
| H1 | Public `recipient` was not bound to the value-carrying output; recipient eligibility was not checked | Server side: every confidential instruction names sender and recipient investors and credentials; both are re-checked at prepare, authorize and accept; `recipient` must be an ACTIVE note owner key registered to the named recipient credential (`/api/zk/note-owner-keys`). Circuit: `confidential_ledger_v3.circom` candidate constrains output 0 owner to `recipient` and change owner to the sender | 026 |
| H2 | Output Merkle root was accepted as asserted by the maker | Dependency-free Poseidon Merkle frontier; the proposal recomputes the root from the locked CURRENT root plus the two output commitments; stale bases are cancelled at finalize; CURRENT roots require a frontier | 022 |
| H3 | Runtime identity owned the schema and could disable append-only triggers | Separate migrator (`MIGRATION_DATABASE_URL`) and least-privilege runtime role (SELECT/INSERT/UPDATE only); production workloads fail closed with `DATABASE_RUNTIME_ROLE_TOO_PRIVILEGED` | — |
| H4 | Prover polling consumed attempts and expired leases were never reclaimed | `poll_count` separate from `attempts`; expired SUBMITTING/VERIFYING leases move to RETRYABLE/FAILED with `PROVER_LEASE_EXPIRED`; bounded poll backoff | 023 |
| M1 | Callbacks trusted a static institution key | Callbacks verify against governed `institution_signing_keys` (`keyId`, lifecycle, validity, revocation); buffered callbacks are re-authorized on drain and a failure opens a CRITICAL incident | 024 |
| M2 | After nullifiers were spent, a wrong root proposal left the transaction stuck in ROOT_PENDING | Permissioned `cancelFinalization` (`transaction.zk.finalize.cancel`, reason recorded) followed by a new maker/checker proposal; a stale base is cancelled at finalize; ROOT_PENDING may only move to SETTLED, so spent value cannot be burned by rejection | 022, 025 |
| M3 | OIDC ID tokens were replayable and not nonce-bound | Single-use login challenge + nonce cookie, token-hash replay rejection, `azp` validation, fixed-window rate limits on anonymous auth and callback endpoints | 027 |
| M4 | Broker/distributor views disclosed transactions across institutions | `originating_institution_id` on transaction intents (immutable); broker and distributor views and evidence packages are scoped to it | 028 |
| M5 | Circuit activation and product contexts were written directly | Maker/checker proposals for circuit activation (pinned artifact only) and product context (with empty genesis root and frontier) | 029 |
| M6 | Sandbox identity switching had no network exposure protection | `HOST` is explicit; sandbox auth on a non-loopback host requires `SANDBOX_CONTAINER_BIND=true`, which production rejects | — |
| L1 | Idempotent settlement replay ran business checks first | Replay is answered before business checks | — |
| L2 | Unauthenticated callbacks revealed institution existence, role assignment and key IDs through distinct error codes | Tenant, institution, role, key and signature rejections all return `401 CALLBACK_AUTHENTICATION_FAILED`; all lookups and one signature verification (against a decoy key when needed) always run; the specific reason stays internal | — |
| L3 | The audit hash chain is per aggregate, so deleting a whole aggregate left no trace | Tenant-wide checkpoints fold every audit event in sequence order into a rolling digest (append-only, anchor recorded once); `scripts/audit-checkpoint.js create/anchor/verify` publishes and re-verifies it. Choosing the external anchor stays a deployment decision — see `AUDIT_CHAIN_ANCHORING.md` | 032 |
| L4 | Retries did not preserve per-aggregate event order | An outbox event is claimable only when every earlier event of the same tenant/aggregate is PUBLISHED; a dead letter blocks its aggregate and raises `OUTBOX_AGGREGATE_BLOCKED_BY_DEAD_LETTER` | 030 |
| L5 | Investor view decrypted every product transaction before filtering | Keyed party pseudonyms (economic-commitment HMAC/KMS MAC) index new transactions; the view decrypts only indexed candidates and still checks party membership; unindexed or rotated-key rows fall back to decrypt-and-check | 031 |
| L7 | Demo exception maker/checker IDs were hardcoded, so one session could approve its own exception | Uses the session `identity.principalId` | — |
| D4 | The fixture notice and the candidate-circuit notice contradicted each other about the test vector's origin | Both now state the same conclusion (the circuit source behind the stored verification key is asserted, not proven); `npm run zk:fixture-provenance` checks what is checkable and prints what is not, and a test fails if the two documents drift apart again | — |
| D5 | Delivery documents quoted stale test counts | README, demo guide and the audit handoff carry the current baseline and say to read the latest `final-acceptance.sh` output instead of a fixed number | — |

Before fixing, H4 (attempt-check violation) and the H1 v2 redirect were
reproduced by failing tests or witness checks.

## Verification

- Full suite against PostgreSQL 16: 190 tests, 0 failures
  (`node --test --test-concurrency=1`).
- New integration tests: `database-privileges`, `prover-job-liveness`,
  `confidential-owner-keys`, `zk-governance`, plus Poseidon frontier vectors
  checked against circomlibjs and the real fixture root.
- The full ZK settlement flow runs as the least-privilege runtime role; the
  same role cannot disable, drop or truncate the nullifier guard.
- v3 circuit evidence (`zk-candidate/evidence/v3-recipient-binding-2026-09-11.json`):
  v2 accepts a redirected-value witness; v3 rejects redirected value and
  change; an honest v3 proof verifies; a relabelled recipient signal fails.
  The ceremony used is single-party and unsafe; its keys must never be used.
- Sandbox HTTP smoke: health READY, demo reset, `verify-auth-http.js`, scoped
  broker/distributor views, maker/checker conflict, callback rejection.

## Upgrade notes

- Migrations 022–032 apply automatically with `scripts/migrate.js`. In
  production, run them with `MIGRATION_DATABASE_URL` and
  `RUNTIME_DATABASE_ROLE` from a separate `RWA_MIGRATION_ENV` file.
- Existing local data: CURRENT roots written before 022 have no frontier,
  instructions written before 026 have no parties, and transactions written
  before 028 have no originating institution. They stay readable but cannot
  progress, and broker views hide them. Reset the Sandbox demo data after
  upgrading.
- OIDC clients must call `/api/oidc/login-challenge` and put the returned
  nonce into the authorization request.
- Callback envelopes may carry `keyId`; it defaults to `primary-v1`.
- Connectors that branched on `INVALID_CALLBACK_SIGNATURE`,
  `UNTRUSTED_CALLBACK_SOURCE`, `UNAUTHORIZED_CALLBACK_SOURCE`,
  `CALLBACK_SIGNING_KEY_UNAVAILABLE` or `CALLBACK_TENANT_MISMATCH` now receive
  `401 CALLBACK_AUTHENTICATION_FAILED`.
- A dead-lettered outbox event now holds back later events of the same
  aggregate until its replay is approved.
- Transactions created before 031 have no party index; investor views still
  show them by decrypting those rows.

## Remaining items

1. v3 circuit: independent circuit audit and a multi-party production
   ceremony before it replaces v2. Until then recipient binding rests on the
   server-side checks.
2. L6 institution IDs are global: in a shared multi-tenant database one tenant
   can register an ID first and block another tenant from using it. Signing
   keys and revocation already require tenant membership, so this is a
   squatting/availability issue, not cross-tenant control. Fixing it needs a
   decision between tenant-scoped institution keys (13 foreign keys) and a
   platform-verified global registry (for example LEI-based).
3. No compensating output exists for a confidential transfer that can never
   be finalized; this needs circuit or governance support.
4. Audit-chain checkpoints must actually be published to an external anchor;
   an unanchored checkpoint table proves nothing on its own.
5. Product context rotation is not supported.
6. `npm audit` has not been run in this environment.
