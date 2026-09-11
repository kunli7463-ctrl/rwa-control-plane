// H3: the runtime database identity must not own the schema.
//
// Append-only guarantees (spent nullifiers, audit chain, proof receipts,
// state history) are enforced by triggers. A table owner can disable those
// triggers, truncate tables or drop constraints, so a compromised runtime
// that owns the schema could erase nullifiers and double spend. Migrations
// therefore run as a separate migrator identity that owns `rwa`, and the
// runtime role receives only row-level DML without DELETE/TRUNCATE/TRIGGER.

const ROLE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;
export const RUNTIME_TABLE_PRIVILEGES = Object.freeze(["SELECT", "INSERT", "UPDATE"]);

function privilegeError(code, message, details = undefined) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

function quoteRole(role) {
  if (typeof role !== "string" || !ROLE_NAME.test(role)) {
    throw privilegeError("INVALID_RUNTIME_DATABASE_ROLE", "runtime database role must be a lowercase PostgreSQL identifier");
  }
  return `"${role}"`;
}

/** Run by the migrator after migrations: grant least-privilege DML to the runtime role. */
export async function grantRuntimePrivileges(pool, { runtimeRole }) {
  const quoted = quoteRole(runtimeRole);
  const client = await pool.connect();
  try {
    const identity = await client.query(
      `SELECT current_user AS migrator,
              EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1) AS runtime_exists,
              (SELECT rolsuper FROM pg_roles WHERE rolname=$1) AS runtime_super`,
      [runtimeRole],
    );
    const row = identity.rows[0];
    if (!row.runtime_exists) {
      throw privilegeError("RUNTIME_DATABASE_ROLE_MISSING", "runtime database role does not exist");
    }
    if (row.migrator === runtimeRole || row.runtime_super) {
      throw privilegeError("RUNTIME_DATABASE_ROLE_TOO_PRIVILEGED", "runtime role must be a separate non-superuser identity");
    }
    await client.query("BEGIN");
    await client.query(`REVOKE ALL ON SCHEMA rwa FROM ${quoted}`);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA rwa FROM ${quoted}`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA rwa FROM ${quoted}`);
    await client.query(`GRANT USAGE ON SCHEMA rwa TO ${quoted}`);
    await client.query(`GRANT ${RUNTIME_TABLE_PRIVILEGES.join(", ")} ON ALL TABLES IN SCHEMA rwa TO ${quoted}`);
    await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA rwa TO ${quoted}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA rwa GRANT ${RUNTIME_TABLE_PRIVILEGES.join(", ")} ON TABLES TO ${quoted}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA rwa GRANT USAGE, SELECT ON SEQUENCES TO ${quoted}`);
    await client.query("COMMIT");
    return { runtimeRole, migrator: row.migrator, tablePrivileges: [...RUNTIME_TABLE_PRIVILEGES] };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

/** Run by every production workload at startup: fail closed if it could bypass DB guards. */
export async function verifyRuntimeDatabasePrivileges(pool) {
  const result = await pool.query(
    `SELECT r.rolname,r.rolsuper,r.rolbypassrls,r.rolcreaterole,
            has_schema_privilege(current_user,'rwa','CREATE') AS schema_create,
            (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='rwa' AND c.relkind IN ('r','p','S','v','m')
                AND pg_has_role(current_user,c.relowner,'MEMBER')) AS owned_relations,
            (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='rwa' AND c.relkind IN ('r','p')
                AND (has_table_privilege(current_user,c.oid,'DELETE')
                  OR has_table_privilege(current_user,c.oid,'TRUNCATE')
                  OR has_table_privilege(current_user,c.oid,'TRIGGER'))) AS destructive_grants,
            pg_has_role(current_user,(SELECT nspowner FROM pg_namespace WHERE nspname='rwa'),'MEMBER') AS schema_owner
     FROM pg_roles r WHERE r.rolname=current_user`,
  );
  const row = result.rows[0];
  const violations = [];
  if (row.rolsuper) violations.push("SUPERUSER");
  if (row.rolbypassrls) violations.push("BYPASSRLS");
  if (row.rolcreaterole) violations.push("CREATEROLE");
  if (row.schema_owner) violations.push("SCHEMA_OWNER");
  if (row.schema_create) violations.push("SCHEMA_CREATE");
  if (row.owned_relations > 0) violations.push("OWNS_RELATIONS");
  if (row.destructive_grants > 0) violations.push("DELETE_TRUNCATE_OR_TRIGGER_GRANTS");
  if (violations.length) {
    throw privilegeError(
      "DATABASE_RUNTIME_ROLE_TOO_PRIVILEGED",
      "production runtime database identity can bypass append-only guards; run migrations as a separate migrator role",
      { role: row.rolname, violations },
    );
  }
  return { role: row.rolname, leastPrivilege: true };
}
