import path from "node:path";
import { fileURLToPath } from "node:url";
import { runMigrations } from "../src/storage/migrate.js";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required");
  process.exitCode = 2;
} else {
  const { Pool } = await import("pg");
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, application_name: "rwa-migrator" });
  try {
    const applied = await runMigrations(pool, { migrationsDir: path.join(root, "db", "migrations") });
    console.log(applied.length ? `Applied: ${applied.join(", ")}` : "Schema is current");
  } finally {
    await pool.end();
  }
}
