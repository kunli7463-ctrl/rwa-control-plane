# Outbox Worker production operations

The worker exposes loopback-only operational endpoints by default:

- `/livez`: process loop is running;
- `/readyz` and `/healthz`: loop is current and PostgreSQL monitoring succeeds;
- `/metrics`: JSON diagnostics;
- `/metrics/prometheus`: Prometheus text exposition.

Alert on the structured `alerts` array or equivalent Prometheus rules. A recent dead letter and a critically old or large backlog are critical. Expired leases are warnings because another worker can reclaim them, but repeated growth indicates crashes, lease sizing errors or a blocked publisher.

Events for one tenant/aggregate are delivered strictly in enqueue order (`enqueue_sequence`). A later event is not claimed while any earlier event for the same aggregate is pending, backing off, leased or dead, so at most one event per aggregate is in flight and other aggregates continue independently. A dead letter therefore stops its aggregate: `OUTBOX_AGGREGATE_BLOCKED_BY_DEAD_LETTER` (critical, `rwa_outbox_blocked_by_dead_letter`) counts the events held behind it until the maker/checker replay is executed.

Readiness deliberately does not fail only because backlog thresholds are exceeded: removing the worker from service would make the backlog worse. It fails when the loop is stale or PostgreSQL cannot be observed. Liveness only reports whether the worker loop is running, so a supervisor can distinguish a dead process from a dependency outage.

Deploy the example systemd unit under a dedicated unprivileged account. Keep the environment file mode `0600`, replace every placeholder, route loopback metrics through an authenticated collector, and never expose the health listener directly to the Internet. `SIGTERM` stops new claims and drains the current batch. The process exits non-zero if draining exceeds `OUTBOX_SHUTDOWN_TIMEOUT_MS`, allowing expired database leases to be reclaimed safely.

Before production, exercise: PostgreSQL disconnect/reconnect, publisher timeout, process kill during a claimed lease, dead-letter approval/replay, two concurrent workers, supervisor restart, and alert delivery. This repository supplies the worker behavior and supervisor template; it does not claim that an external alerting service is connected.

