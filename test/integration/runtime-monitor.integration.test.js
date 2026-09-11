import test from 'node:test';
import assert from 'node:assert/strict';
import { RuntimeOperationalMonitor } from '../../src/observability/runtime-monitor.js';

test('runtime metrics probe reads real PostgreSQL with read-only session and exposes visibility explicitly',
  { skip: !process.env.DATABASE_URL }, async () => {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1,
      options: '-c default_transaction_read_only=on', connectionTimeoutMillis: 1000,
      statement_timeout: 1000, query_timeout: 1500 });
    const monitor = new RuntimeOperationalMonitor({ pool });
    try {
      assert.equal((await pool.query('SHOW default_transaction_read_only')).rows[0].default_transaction_read_only, 'on');
      const metrics = await monitor.snapshot();
      assert.equal(metrics.rwa_database_monitor_up, 1);
      assert.ok(metrics.rwa_database_connections > 0);
      assert.ok(metrics.rwa_database_size_bytes > 0);
      assert.ok([0, 1].includes(metrics.rwa_database_details_visible));
      if (!metrics.rwa_database_details_visible) {
        assert.equal(metrics.rwa_database_lock_waiters, undefined);
        assert.equal(metrics.rwa_database_oldest_transaction_seconds, undefined);
      }
    } finally { await monitor.close(); }
  });
