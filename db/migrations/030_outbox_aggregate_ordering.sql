-- L4: events for one aggregate are delivered in the order they were enqueued.
--
-- A retry (FAILED with backoff), an expired lease or a dead letter must not let
-- a later event for the same tenant/aggregate overtake an earlier one. The
-- enqueue sequence is assigned at insert; writes for one aggregate are already
-- serialized by the aggregate's own row locks, so sequence order is commit
-- order for that aggregate.

ALTER TABLE rwa.outbox_events
  ADD COLUMN IF NOT EXISTS enqueue_sequence bigint GENERATED ALWAYS AS IDENTITY;

CREATE INDEX IF NOT EXISTS outbox_aggregate_order_idx
  ON rwa.outbox_events(tenant_id, aggregate_id, enqueue_sequence)
  WHERE status <> 'PUBLISHED';
