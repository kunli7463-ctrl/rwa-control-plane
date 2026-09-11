import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

async function migrationFiles(migrationsDir) {
  const filenames = (await readdir(migrationsDir))
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
  return Promise.all(filenames.map(async (filename) => {
    const sql = await readFile(path.join(migrationsDir, filename), "utf8");
    return { filename, sql, checksum: createHash("sha256").update(sql).digest("hex") };
  }));
}

export async function verifyMigrations(pool, { migrationsDir }) {
  let rows;
  try {
    rows = await pool.query("SELECT filename,checksum FROM rwa.schema_migrations ORDER BY filename");
  } catch (cause) {
    const error = new Error("database schema is not initialized by the approved migrator", { cause });
    error.code = "DATABASE_MIGRATION_REQUIRED";
    throw error;
  }
  const expected = await migrationFiles(migrationsDir);
  const actual = new Map(rows.rows.map((row) => [row.filename, row.checksum]));
  for (const file of expected) {
    if (actual.get(file.filename) !== file.checksum) {
      const error = new Error(`database migration is missing or has drifted: ${file.filename}`);
      error.code = "DATABASE_MIGRATION_DRIFT";
      throw error;
    }
  }
  const known = new Set(expected.map((file) => file.filename));
  if (rows.rows.some((row) => !known.has(row.filename))) {
    const error = new Error("database contains an unknown migration version");
    error.code = "DATABASE_MIGRATION_DRIFT";
    throw error;
  }
  return { current: true, migrationCount: expected.length, latest: expected.at(-1)?.filename ?? null };
}

export async function runMigrations(pool, { migrationsDir }) {
  await pool.query("CREATE SCHEMA IF NOT EXISTS rwa");
  await pool.query(`CREATE TABLE IF NOT EXISTS rwa.schema_migrations (
    filename text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`);

  const applied = [];
  for (const { filename, sql, checksum } of await migrationFiles(migrationsDir)) {
    const existing = await pool.query(
      "SELECT checksum FROM rwa.schema_migrations WHERE filename=$1",
      [filename],
    );
    if (existing.rowCount === 1) {
      if (existing.rows[0].checksum !== checksum) {
        throw new Error(`applied migration checksum mismatch: ${filename}`);
      }
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO rwa.schema_migrations(filename, checksum) VALUES ($1,$2)",
        [filename, checksum],
      );
      await client.query("COMMIT");
      applied.push(filename);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }
  return applied;
}
