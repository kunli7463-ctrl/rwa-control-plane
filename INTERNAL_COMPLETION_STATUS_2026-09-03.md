# Internal completion status — 2026-09-03

Latest continuation: see `INTERNAL_CLOSEOUT_2026-09-04.md` for the four-market draft
module, release/SBOM evidence and actual local Circom rebuild. Counts below are historical;
current full PostgreSQL regression is 161/161 with zero failures/skips. No overall production
or independent-audit completion is claimed.

## Current phase

Phases 1 and 2 have application-code acceptance. Phase 3 local pressure/fault
tests passed (142/142 full suite and 16/16 matrix at 1,000 events / 12 workers).
Host-owned PostgreSQL stop/start acceptance was subsequently reported passed by
the user. Phase 4 worker monitoring has passed native local acceptance; wider
production monitoring remains tracked separately.
Earlier counts below are historical snapshots, not the current test target.

## Changes completed

- Added `scripts/local-runtime.sh` as the single local runtime discovery contract.
- Removed developer-specific `/Users/lixun/...` paths from start, stop, verify,
  backup and restore scripts.
- Added environment overrides for Node, PostgreSQL binaries/data, endpoint,
  users and database name.
- Enforced Node.js major version 22 before migration or acceptance.
- Added a regression test that prevents developer-specific absolute paths from
  returning to the local acceptance scripts.
- Corrected the database-existence probe after host-terminal acceptance exposed
  that `psql -c` does not expand `:'database'`. The script now validates the
  database identifier and safely detects an existing database before `createdb`.
- Added a regression assertion for that exact host-only failure mode.
- Corrected two full-acceptance test baselines exposed only with PostgreSQL:
  the production-auth test now expects migration 021, and the forged-signature
  test uses an issuance time inside the newly registered primary key's validity
  window so it reaches the intended Ed25519 rejection instead of failing an
  earlier, unrelated time-window guard.
- Updated README and product completion evidence.

## Verification completed inside Codex

```text
tests:   130
passed:  115
failed:  0
skipped: 15 PostgreSQL integration tests
```

The 15 skips are controlled by the test suite when PostgreSQL is unavailable.
The ordinary Homebrew `node` command is currently broken because a Homebrew
library still references `libsimdutf.34.dylib`; the project-local isolated
Node.js 22.23.2 works and produced the result above.

Codex cannot start this macOS PostgreSQL instance because its sandbox blocks
the required System V shared-memory call. The server log records
`could not create shared memory segment: Operation not permitted`. This occurs
before application code or migrations run and is not an application assertion
failure.

## Host-terminal acceptance completed

On 2026-09-03 the full acceptance command was run in Warp with the local
PostgreSQL instance. Reported result:

```text
tests:   130
passed:  130
failed:  0
skipped: 0
FINAL_ACCEPTANCE_OK
migration=021_product_evidence_signature_verification.sql
```

Phase 1 acceptance is closed.

## Re-running host-terminal acceptance

Run in Warp:

```sh
cd /Users/lixun/Documents/Codex/2026-08-19/mport-hashlib-import-hmac-import-os/product/demo
./scripts/final-acceptance.sh
```

The retained acceptance contract requires:

- the latest migration is `021_product_evidence_signature_verification.sql`;
- all currently discovered tests pass (do not hard-code a historic count);
- zero failures;
- zero skipped tests;
- the script prints `FINAL_ACCEPTANCE_OK`.

Do not repair the Homebrew `node` installation merely to run this project. The
acceptance script resolves the isolated Node 22 runtime first. If another host
is used, set `RWA_NODE_BIN`, `RWA_PG_PREFIX` and `RWA_PG_DATA` explicitly.

## Historical phase 2

Production deployment automation and fail-closed configuration packaging.

### Phase 2 implementation completed so far

- Added `src/production-preflight.js` as the production deployment contract.
  It requires the full Groth16/isolated-prover path, rejects unresolved
  placeholders and reserved endpoints, requires a non-loopback PostgreSQL
  endpoint, absolute mounted provider paths and exact tenant equality across
  Web, prover and Outbox workloads.
- Added `scripts/validate-production-env.js`; it parses one explicit env file,
  rejects duplicate or malformed keys and prints only a redacted deployment
  summary (never database passwords or service tokens).
- Added `deploy/compose/production.example.yaml` with separate preflight,
  artifact-check, migration, Web, Outbox and prover services. Runtime containers
  are non-root, read-only, capability-free and gated on successful one-shot
  checks. Only the Web port is published, and only on loopback for a TLS proxy.
- Added `PRODUCTION_DEPLOYMENT.md` with the required deployment sequence and
  explicit external-dependency boundary.
- Closed the Outbox startup fallback: `NODE_ENV=production` can no longer run
  with an implicit Sandbox deployment profile, and Outbox tenant scope must
  match the main tenant.
- Added production placeholder rejection to the runtime itself so bypassing
  the standalone preflight does not make placeholder values acceptable.
- Added `scripts/production-deploy.sh`, which refuses mutable image tags and
  missing mount paths, then fixes the execution order as Compose validation,
  configuration preflight, artifact verification, migration and health-gated
  workload startup. It deliberately performs no automatic schema rollback.

Phase 2 regression result inside Codex:

```text
tests:   136
passed:  121
failed:  0
skipped: 15 PostgreSQL integration tests
```

The new 136-test PostgreSQL suite was subsequently reported passing in Warp
with zero failures and zero skips. Phase 2 application-code acceptance is
closed. Docker/Compose is not installed in the current Codex host environment,
so the Compose document has passed source-contract tests but not a real image
build or `docker compose config`; that remains a deployment-environment
acceptance item and is not represented as completed.

## Phase 3 closeout

- Added `scripts/run-pressure-and-faults.sh` and `RESILIENCE_TESTING.md`.
- Found and reproduced Outbox claim retry exhaustion (`40001`) under six workers.
- Queue claim transactions for Outbox and prover now use Read Committed plus
  row locking; financial state transitions remain Serializable.
- Added queue commit/rollback/release tests, 500-call re-entry tests and prover timeout.
- Retained runs: 16/16 at 100 events / 6 workers; 16/16 at 1,000 events / 12 workers.
- Full PostgreSQL suite after repair: 142 passed, zero failures, zero skips.
- `final-acceptance.sh` could not signal the host-owned database PID from the
  sandbox; direct full tests succeeded against the running database. The wrapper
  is not weakened or replaced with a fake success marker. Restart verification
  must still run in the owning host terminal.

## Phase 4 implementation and acceptance boundary

Monitoring pack: explicit deployment labels, worker readiness metrics, Prometheus
rules, Grafana dashboard/provisioning, private Compose overlay and runbook.
Node tests validate metric wiring and configuration contracts. Native Prometheus
rule evaluation and Grafana/container startup must pass separately; source tests
are not equivalent to these runtime checks. Notification receiver delivery is
not configured by default and must never be described as operational paging.

Current run: `verify-local-postgres.sh` completed 146/146 tests, zero failures,
zero skips. Monitoring Node subset: 8/8. `verify-monitoring.sh` then correctly
exited 2 because promtool is unavailable. `final-acceptance.sh` still cannot
signal host PID 50726 (Operation not permitted); no restart-success claim made.
Grafana JSON/provisioning and Prometheus positive/healthy/recovery fixtures are
delivered but native rendering/rule execution remains pending.

## Remaining internal roadmap

4. Finish monitoring runtime and notification acceptance.
5. Four market profiles: Hong Kong, Singapore, Malaysia, UAE. Malaysia/UAE are
   intended operating bases; this does not imply four company registrations.
6. Supply-chain review, SBOM and release governance.
7. ZK reproducible build and audit package.
8. Independent full-repository regression, cleanup and acceptance.

## Latest phase 4 result (supersedes pending-tool notes above)

Official SHA-256 verified native tools are now installed under `.local-tools/`.
Node monitoring tests: 10/10. promtool: 22 rules and 26 scenario fixtures passed.
amtool notification config validation passed. Isolated native Prometheus,
Alertmanager and Grafana started; dashboard API/provisioning, datasource and all
panel queries passed. Firing and resolved notifications reached only the local
authenticated synthetic receiver. Services were stopped after the test.
Full PostgreSQL regression: 148/148, zero failures, zero skips.
See `MONITORING_ACCEPTANCE_2026-09-03.md` for evidence and remaining limits.

## Phase 4 Web/database/host increment (latest)

PostgreSQL full regression: 155/155, zero failures/skips. Monitoring subset: 16/16.
Native monitoring now validates 34 rules, 40 scenario fixtures and 26 Grafana panels.
Web metrics are opt-in on a separate private listener. Database detail visibility is explicit;
failed probes omit stale statistics. Host/filesystem metrics are not remote DB disk or cgroup limits.
See `WEB_MONITORING_ACCEPTANCE_2026-09-03.md`. Native synthetic notification acceptance
does not replace production network/receiver acceptance or Grafana browser visual QA.
