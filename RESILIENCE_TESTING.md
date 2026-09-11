# Pressure and failure-injection acceptance

This stage uses only synthetic, uniquely named local records. It must not be
pointed at a customer, shared staging or production database.

## Covered properties

- 500 simultaneous `runOnce` calls cannot overlap one Outbox dispatch or one
  prover job inside a worker process.
- Multiple PostgreSQL Outbox workers drain a configurable synthetic backlog
  through `FOR UPDATE SKIP LOCKED` without duplicate delivery or stranded
  leases in the no-fault path.
- Existing failure tests cover publish failure, retry delay, dead-lettering,
  lease expiry/reclaim, stale-owner rejection and maker/checker replay.
- Existing PostgreSQL resilience tests force real serialization conflicts and
  terminate a pooled backend, verifying retry correctness and connection
  replacement without replaying the failed operation.
- Existing health tests prove that database-monitor failures and unexpected
  worker cycle errors make readiness fail closed while liveness remains
  observable.

## Run locally

```sh
./scripts/run-pressure-and-faults.sh
```

Optional bounded load controls:

```sh
RWA_STRESS_EVENT_COUNT=1000 RWA_STRESS_WORKERS=12 ./scripts/run-pressure-and-faults.sh
```

The hard limits are 5,000 events and 32 workers. Passing this suite is a local
correctness and resilience result, not a production capacity claim. Production
SLO/load limits require representative infrastructure, latency, provider quotas
and institution-approved failure drills.

## Retained evidence (2026-09-03)

The first six-worker run reproduced PostgreSQL 40001 retry exhaustion in Outbox
claiming. Outbox and prover lease claims now use short Read Committed transactions
with row locks; financial mutations remain Serializable. After repair:

- 100 events / 6 workers: 16 passed, 0 failed.
- 1,000 events / 12 workers: 16 passed, 0 failed; no duplicates or stranded leases
  in the no-fault publishing path (not an exactly-once transport guarantee).
- Full PostgreSQL test suite: 142 passed, 0 failed, 0 skipped.

Host stop/start is separate from the above tests. Do not change final acceptance
to print success if stop/start was denied or skipped.
