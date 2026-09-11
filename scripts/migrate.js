import path from "node:path";
import { fileURLToPath } from "node:url";
import { grantRuntimePrivileges } from "../src/storage/database-privileges.js";
import { runMigrations } from "../src/storage/migrate.js";

const deploymentProfile = process.env.DEPLOYMENT_PROFILE ?? "sandbox";
const production = deploymentProfile === "production";
// Production migrations run as a dedicated schema-owning identity. The
// runtime DATABASE_URL is never used for DDL there (H3).
const connectionString = process.env.MIGRATION_DATABASE_URL ?? (production ? null : process.env.DATABASE_URL);
const runtimeRole = process.env.RUNTIME_DATABASE_ROLE ?? null;

if (!connectionString) {
  console.error(production
    ? "MIGRATION_DATABASE_URL is required for production migrations"
    : "MIGRATION_DATABASE_URL or DATABASE_URL is required");
  process.exitCode = 2;
} else if (production && !runtimeRole) {
  console.error("RUNTIME_DATABASE_ROLE is required so production migrations grant least-privilege runtime access");
  process.exitCode = 2;
} else {
  const { Pool } = await import("pg");
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pool = new Pool({ connectionString, application_name: "rwa-migrator" });
  try {
    const applied = await runMigrations(pool, { migrationsDir: path.join(root, "db", "migrations") });
    console.log(applied.length ? `Applied: ${applied.join(", ")}` : "Schema is current");
    if (runtimeRole) {
      const grant = await grantRuntimePrivileges(pool, { runtimeRole });
      console.log(`Runtime role ${grant.runtimeRole} granted ${grant.tablePrivileges.join(", ")} (migrator ${grant.migrator})`);
    }
  } catch (error) {
    console.error(`MIGRATION_FAILED ${error.code ?? ""}: ${error.message}`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
