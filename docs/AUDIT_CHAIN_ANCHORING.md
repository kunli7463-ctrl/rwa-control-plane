# Audit chain checkpoints and external anchoring

Audit events are hash-chained per aggregate (`previous_hash` → `event_hash`), so
editing or removing one event inside an aggregate breaks that aggregate's chain.
Removing an aggregate's events entirely leaves the remaining chains valid, and
nothing inside the database proves that the set of aggregates is complete
(review finding L3).

Checkpoints close that gap. `rwa.audit_chain_checkpoints` folds every audit
event of a tenant, in global sequence order, into a rolling digest:

```
digest(n) = sha256("rwa.audit-chain-checkpoint.v1" || digest(n-1) || throughSequenceId || eventCount || event_hash…)
```

Audit writes take a shared tenant advisory lock and a checkpoint takes the
exclusive one, so no event can commit below a recorded boundary afterwards.
Checkpoints are append-only: they cannot be deleted or edited, and the external
anchor may be written once.

## Operating it

```sh
# 1. Fold all new events and print the digest to publish.
TENANT_ID=<tenant> DATABASE_URL=<url> node scripts/audit-checkpoint.js create --by ops-operator

# 2. Publish that digest to the external anchor (notary, timestamping service,
#    counterparty, or a witnessed ledger), then record where it went.
TENANT_ID=<tenant> DATABASE_URL=<url> node scripts/audit-checkpoint.js anchor \
  --checkpoint 7 --service notary.example --reference receipt-123

# 3. Recompute every checkpoint from the stored events. Exit code 1 and a
#    reason (DIGEST_MISMATCH, EVENT_COUNT_MISMATCH, CHECKPOINT_CHAIN_BROKEN)
#    mean the stored history no longer reproduces a published digest.
TENANT_ID=<tenant> DATABASE_URL=<url> node scripts/audit-checkpoint.js verify
```

Run `create` on a schedule (hourly is a reasonable starting point), anchor at
least daily, and run `verify` before every evidence export, after any restore
from backup, and as part of incident response. Keep the printed digests outside
the database — a digest that exists only in the same database proves nothing.

## What this does and does not prove

- It proves the audit history has not been edited or truncated **since a digest
  was published somewhere the operator cannot rewrite**.
- It does not prove the events were correct when written, and an unanchored
  checkpoint proves nothing on its own: an operator with database ownership
  could recompute the whole checkpoint table.
- Choosing the anchor (notary, qualified timestamping authority, counterparty
  co-signature, public ledger) and the retention of anchor receipts is a
  deployment decision and remains an external dependency.
