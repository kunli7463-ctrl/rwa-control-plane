function threshold(value, name) {
  if (!Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be non-negative`);
  return value;
}

export class ProverOperationalMonitor {
  constructor(store, { tenantId, warningBacklog = 20, criticalBacklog = 100,
    warningOldestAgeMs = 120_000, criticalOldestAgeMs = 600_000,
    failedLookbackMs = 300_000, now = () => new Date() } = {}) {
    if (!store?.pool) throw new TypeError("PostgreSQL store is required");
    if (typeof tenantId !== "string" || !tenantId) throw new TypeError("tenantId is required");
    for (const [value, name] of [[warningBacklog, "warningBacklog"], [criticalBacklog, "criticalBacklog"],
      [warningOldestAgeMs, "warningOldestAgeMs"], [criticalOldestAgeMs, "criticalOldestAgeMs"],
      [failedLookbackMs, "failedLookbackMs"]]) threshold(value, name);
    if (criticalBacklog < warningBacklog || criticalOldestAgeMs < warningOldestAgeMs) {
      throw new TypeError("critical prover thresholds must not be lower than warning thresholds");
    }
    Object.assign(this, { store, tenantId, warningBacklog, criticalBacklog, warningOldestAgeMs,
      criticalOldestAgeMs, failedLookbackMs, now });
  }

  async snapshot() {
    const result = await this.store.pool.query(
      `SELECT
         count(*) FILTER (WHERE state IN ('QUEUED','REMOTE_PENDING','RETRYABLE'))::int AS backlog,
         count(*) FILTER (WHERE state IN ('SUBMITTING','VERIFYING'))::int AS active,
         count(*) FILTER (WHERE state='RETRYABLE')::int AS retryable,
         count(*) FILTER (WHERE state='FAILED' AND updated_at>=clock_timestamp()-($2::bigint*interval '1 millisecond'))::int AS recent_failed,
         count(*) FILTER (WHERE lease_expires_at<clock_timestamp())::int AS expired_leases,
         COALESCE(EXTRACT(EPOCH FROM (clock_timestamp()-min(requested_at) FILTER
           (WHERE state IN ('QUEUED','REMOTE_PENDING','RETRYABLE'))))*1000,0)::bigint AS oldest_backlog_age_ms
       FROM rwa.prover_jobs WHERE tenant_id=$1`,
      [this.tenantId, this.failedLookbackMs],
    );
    const metrics = {
      backlog: result.rows[0].backlog,
      active: result.rows[0].active,
      retryable: result.rows[0].retryable,
      recentFailed: result.rows[0].recent_failed,
      expiredLeases: result.rows[0].expired_leases,
      oldestBacklogAgeMs: Number(result.rows[0].oldest_backlog_age_ms),
      sampledAt: this.now().toISOString(),
    };
    return { ...metrics, alerts: this.#alerts(metrics) };
  }

  #alerts(metrics) {
    const alerts = [];
    const add = (severity, code, value) => alerts.push({ severity, code, value });
    if (metrics.backlog >= this.criticalBacklog) add("CRITICAL", "PROVER_BACKLOG_HIGH", metrics.backlog);
    else if (metrics.backlog >= this.warningBacklog) add("WARNING", "PROVER_BACKLOG_ELEVATED", metrics.backlog);
    if (metrics.oldestBacklogAgeMs >= this.criticalOldestAgeMs) add("CRITICAL", "PROVER_JOB_STALE", metrics.oldestBacklogAgeMs);
    else if (metrics.oldestBacklogAgeMs >= this.warningOldestAgeMs) add("WARNING", "PROVER_JOB_DELAYED", metrics.oldestBacklogAgeMs);
    if (metrics.expiredLeases > 0) add("WARNING", "PROVER_EXPIRED_LEASES", metrics.expiredLeases);
    if (metrics.recentFailed > 0) add("CRITICAL", "PROVER_RECENT_FAILURES", metrics.recentFailed);
    return alerts;
  }
}

export function proverPrometheusMetrics(worker, operations) {
  return `${[
    "# TYPE rwa_prover_worker_running gauge",
    `rwa_prover_worker_running ${worker.running ? 1 : 0}`,
    "# TYPE rwa_prover_worker_ready gauge",
    `rwa_prover_worker_ready ${worker.ready ? 1 : 0}`,
    `rwa_prover_worker_cycles_total ${worker.cycles}`,
    `rwa_prover_worker_processed_total ${worker.processed}`,
    `rwa_prover_worker_verified_total ${worker.verified}`,
    `rwa_prover_worker_retryable_total ${worker.retryable}`,
    `rwa_prover_worker_failed_total ${worker.failed}`,
    `rwa_prover_worker_cycle_errors_total ${worker.cycleErrors}`,
    `rwa_prover_backlog ${operations.backlog}`,
    `rwa_prover_active ${operations.active}`,
    `rwa_prover_expired_leases ${operations.expiredLeases}`,
    `rwa_prover_recent_failures ${operations.recentFailed}`,
    `rwa_prover_oldest_job_age_milliseconds ${operations.oldestBacklogAgeMs}`,
  ].join("\n")}\n`;
}
