# Isolated Prover operations

The control plane never accepts raw witness material. A broker queues only an
opaque `vault://`, `hsm://` or `kmsref://` reference. The encrypted reference is
decrypted by the Prover worker, sent over HTTPS to a pinned Prover service, and
the returned proof is still verified by the independently pinned local Groth16
verifier before any nullifier or output commitment is committed.

Required production settings are `ZK_MODE=groth16`, `PROVER_MODE=isolated`,
`PROVER_ENDPOINT`, `PROVER_SERVICE_TOKEN` and `PROVER_EXPECTED_SERVICE_ID`.
The database and Prover worker are both tenant-scoped. A worker cannot claim a
job belonging to another tenant.

Run the worker under process supervision:

```sh
npm run worker:prover
curl --fail http://127.0.0.1:8771/livez
curl --fail http://127.0.0.1:8771/readyz
curl --fail http://127.0.0.1:8771/metrics/prometheus
```

Operational states are `QUEUED → SUBMITTING → REMOTE_PENDING → VERIFYING →
VERIFIED`. Transient errors enter `RETRYABLE` with capped exponential delay;
permanent remote failures enter `FAILED`. `attempts` counts failed or
abandoned attempts only (terminal after 8); remote status polls are counted in
`poll_count` and back off from 2s to 30s, so a long-running proof never
exhausts its retry budget or the `attempts <= 32` constraint. Every worker
cycle first moves `SUBMITTING`/`VERIFYING` jobs whose lease has expired (a
crashed or stalled worker) to `RETRYABLE` with `PROVER_LEASE_EXPIRED`; the
resubmission reuses the job id as the idempotent remote request id, and the
stalled worker can no longer overwrite the recovered job. A successful remote response does not imply acceptance: all 13
signals, the approved artifact and the proof are verified again through the
existing atomic ZK settlement gate.

Alert on `PROVER_BACKLOG_HIGH`, `PROVER_JOB_STALE`, `PROVER_EXPIRED_LEASES` and
`PROVER_RECENT_FAILURES`. Never expose the worker health port publicly, never
log witness references, and rotate the Prover token independently from the
Groth16 artifact and envelope-encryption keys.
