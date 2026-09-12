function finiteThreshold(value, name) {
  if (!Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be non-negative`);
  return value;
}

export class OutboxOperationalMonitor {
  constructor(store, {
    tenantId = null,
    warningBacklog = 100,
    criticalBacklog = 1_000,
    warningOldestAgeMs = 60_000,
    criticalOldestAgeMs = 300_000,
    deadLookbackMs = 300_000,
    now = () => new Date(),
  } = {}) {
    if (!store?.pool) throw new TypeError("PostgreSQL store is required");
    for (const [value, name] of [[warningBacklog, "warningBacklog"], [criticalBacklog, "criticalBacklog"],
      [warningOldestAgeMs, "warningOldestAgeMs"], [criticalOldestAgeMs, "criticalOldestAgeMs"],
      [deadLookbackMs, "deadLookbackMs"]]) finiteThreshold(value, name);
    if (criticalBacklog < warningBacklog || criticalOldestAgeMs < warningOldestAgeMs) {
      throw new TypeError("critical outbox thresholds must not be lower than warning thresholds");
    }
    Object.assign(this, { store, tenantId, warningBacklog, criticalBacklog, warningOldestAgeMs,
      criticalOldestAgeMs, deadLookbackMs, now });
  }

  async snapshot() {
    const result = await this.store.pool.query(
      `SELECT
         count(*) FILTER (WHERE status IN ('PENDING','FAILED'))::int AS backlog,
         count(*) FILTER (WHERE status='CLAIMED')::int AS claimed,
         count(*) FILTER (WHERE status='CLAIMED' AND lease_expires_at<clock_timestamp())::int AS expired_leases,
         count(*) FILTER (WHERE status='DEAD' AND dead_lettered_at>=clock_timestamp()-($2::bigint*interval '1 millisecond'))::int AS recent_dead,
         (SELECT count(*)::int FROM rwa.outbox_events b
           WHERE ($1::text IS NULL OR b.tenant_id=$1) AND b.status IN ('PENDING','FAILED')
             AND EXISTS (SELECT 1 FROM rwa.outbox_events d
               WHERE d.tenant_id=b.tenant_id AND d.aggregate_id=b.aggregate_id
                 AND d.status='DEAD' AND d.enqueue_sequence<b.enqueue_sequence)) AS blocked_by_dead_letter,
         COALESCE(EXTRACT(EPOCH FROM (clock_timestamp()-min(created_at) FILTER
           (WHERE status IN ('PENDING','FAILED'))))*1000,0)::bigint AS oldest_backlog_age_ms
       FROM rwa.outbox_events WHERE ($1::text IS NULL OR tenant_id=$1)`,
      [this.tenantId, this.deadLookbackMs],
    );
    const metrics = {
      backlog: result.rows[0].backlog,
      claimed: result.rows[0].claimed,
      expiredLeases: result.rows[0].expired_leases,
      recentDead: result.rows[0].recent_dead,
      blockedByDeadLetter: result.rows[0].blocked_by_dead_letter ?? 0,
      oldestBacklogAgeMs: Number(result.rows[0].oldest_backlog_age_ms),
      sampledAt: this.now().toISOString(),
    };
    return { ...metrics, alerts: this.#alerts(metrics) };
  }

  #alerts(metrics) {
    const alerts = [];
    const add = (severity, code, value) => alerts.push({ severity, code, value });
    if (metrics.backlog >= this.criticalBacklog) add("CRITICAL", "OUTBOX_BACKLOG_HIGH", metrics.backlog);
    else if (metrics.backlog >= this.warningBacklog) add("WARNING", "OUTBOX_BACKLOG_ELEVATED", metrics.backlog);
    if (metrics.oldestBacklogAgeMs >= this.criticalOldestAgeMs) add("CRITICAL", "OUTBOX_OLDEST_EVENT_STALE", metrics.oldestBacklogAgeMs);
    else if (metrics.oldestBacklogAgeMs >= this.warningOldestAgeMs) add("WARNING", "OUTBOX_OLDEST_EVENT_DELAYED", metrics.oldestBacklogAgeMs);
    if (metrics.expiredLeases > 0) add("WARNING", "OUTBOX_EXPIRED_LEASES", metrics.expiredLeases);
    if (metrics.recentDead > 0) add("CRITICAL", "OUTBOX_RECENT_DEAD_LETTERS", metrics.recentDead);
    if (metrics.blockedByDeadLetter > 0) add("CRITICAL", "OUTBOX_AGGREGATE_BLOCKED_BY_DEAD_LETTER", metrics.blockedByDeadLetter);
    return alerts;
  }
}

export function prometheusMetrics(workerSnapshot, operationalSnapshot = null) {
  const lines = [
    "# TYPE rwa_outbox_worker_running gauge",
    `rwa_outbox_worker_running ${workerSnapshot.running ? 1 : 0}`,
    "# TYPE rwa_outbox_worker_ready gauge",
    `rwa_outbox_worker_ready ${workerSnapshot.ready ? 1 : 0}`,
    "# TYPE rwa_outbox_worker_cycles_total counter",
    `rwa_outbox_worker_cycles_total ${workerSnapshot.cycles}`,
    `rwa_outbox_worker_published_total ${workerSnapshot.published}`,
    `rwa_outbox_worker_failed_total ${workerSnapshot.failed}`,
    `rwa_outbox_worker_dead_total ${workerSnapshot.dead}`,
    `rwa_outbox_worker_cycle_errors_total ${workerSnapshot.cycleErrors}`,
  ];
  if (operationalSnapshot) lines.push(
    `rwa_outbox_backlog ${operationalSnapshot.backlog}`,
    `rwa_outbox_claimed ${operationalSnapshot.claimed}`,
    `rwa_outbox_expired_leases ${operationalSnapshot.expiredLeases}`,
    `rwa_outbox_recent_dead_letters ${operationalSnapshot.recentDead}`,
    `rwa_outbox_blocked_by_dead_letter ${operationalSnapshot.blockedByDeadLetter ?? 0}`,
    `rwa_outbox_oldest_event_age_milliseconds ${operationalSnapshot.oldestBacklogAgeMs}`,
  );
  return `${lines.join("\n")}\n`;
}
