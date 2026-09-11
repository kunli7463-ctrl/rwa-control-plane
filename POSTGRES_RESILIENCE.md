# PostgreSQL resilience and recovery boundary

## Automated checks

The integration suite creates an isolated product and proves that concurrent Serializable transactions preserve every committed version increment while exercising real `40001` retries. A separate test terminates one backend, verifies that the in-flight query fails, and then verifies that the pool establishes a replacement connection. The application intentionally does not retry arbitrary connection failures because commit outcome may be unknown; callers must reconcile by idempotency key before deciding whether to resubmit.

## Local logical backup drill

Create a consistent custom-format backup and checksum:

```sh
./scripts/backup-local-postgres.sh
```

Verify it by restoring into a uniquely named temporary database, checking core tables, and deleting only that temporary database:

```sh
./scripts/verify-local-backup-restore.sh /absolute/path/to/rwa_control_plane_TIMESTAMP.dump
```

The restore verifier never targets `rwa_control_plane`. It requires an absolute backup path and checksum sidecar, validates a strict temporary database prefix, and installs an exit trap before creating the temporary database.

## PITR and disaster recovery

Logical dumps are not PITR. Production requires managed PostgreSQL or an independently operated cluster with continuous WAL archiving, encrypted base backups, cross-account/cross-region copies, retention locks, tested restore credentials and documented RPO/RTO. Validate PITR by restoring to an isolated environment at timestamps immediately before and after a known marker transaction, then verify migration checksums, audit-chain continuity, ledger/register equality, outbox state and encrypted-payload decryptability with recovery-authorized KMS keys.

Do not enable or claim PITR from application code alone. WAL storage, replication, backup encryption, KMS recovery and regional failover belong to the chosen database platform. Record every drill’s backup identifier, target timestamp, actual RPO/RTO, integrity-query output, approvers and deletion evidence for the isolated restore environment.

