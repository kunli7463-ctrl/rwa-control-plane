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
| L7 | Demo exception maker/checker IDs were hardcoded, so one session could approve its own exception | Uses the session `identity.principalId` | — |

Before fixing, H4 (attempt-check violation) and the H1 v2 redirect were
reproduced by failing tests or witness checks.

## Verification

- Full suite against PostgreSQL 16: 187 tests, 0 failures
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

- Migrations 022–029 apply automatically with `scripts/migrate.js`. In
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

## Remaining items

1. v3 circuit: independent circuit audit and a multi-party production
   ceremony before it replaces v2. Until then recipient binding rests on the
   server-side checks.
2. L2 unauthenticated callbacks query the database before signature checks and reveal institution/role existence through error codes.
3. L3 audit hash chain is not anchored externally.
4. L4 Outbox retries do not preserve per-aggregate event order.
5. L5 investor view decrypts every product transaction before filtering.
6. L6 institution IDs are global rather than tenant-scoped.
7. No compensating output exists for a confidential transfer that can never
   be finalized; this needs circuit or governance support.
8. Product context rotation is not supported.
9. `npm audit` has not been run in this environment.
