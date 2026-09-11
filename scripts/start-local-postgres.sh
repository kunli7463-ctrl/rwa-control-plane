#!/bin/zsh
set -euo pipefail

source "${0:A:h}/local-runtime.sh"
PG_LOG="$PG_DATA/server.log"

require_executable "$PG_PREFIX/bin/postgres" "PostgreSQL server"
require_executable "$PG_PREFIX/bin/initdb" "PostgreSQL initdb"
require_executable "$PG_PREFIX/bin/pg_ctl" "PostgreSQL pg_ctl"
require_executable "$PG_PREFIX/bin/pg_isready" "PostgreSQL pg_isready"
require_executable "$PG_PREFIX/bin/psql" "PostgreSQL psql"
require_executable "$PG_PREFIX/bin/createdb" "PostgreSQL createdb"
require_identifier "$PG_ADMIN_USER" "PostgreSQL admin user"
require_identifier "$PG_APP_USER" "PostgreSQL application user"
require_identifier "$PG_DATABASE" "PostgreSQL database"

mkdir -p "${PG_DATA:h}"

if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
  "$PG_PREFIX/bin/initdb" \
    -D "$PG_DATA" \
    --username="$PG_ADMIN_USER" \
    --encoding=UTF8 \
    --locale=C \
    --auth-local=trust \
    --auth-host=trust
fi

if ! "$PG_PREFIX/bin/pg_isready" -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1; then
  "$PG_PREFIX/bin/pg_ctl" -D "$PG_DATA" -l "$PG_LOG" -o "-h $PG_HOST -p $PG_PORT" start
fi

"$PG_PREFIX/bin/psql" -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d postgres \
  -v ON_ERROR_STOP=1 -v app_user="$PG_APP_USER" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec
SQL

if [[ "$("$PG_PREFIX/bin/psql" -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d postgres \
  -tAc "SELECT 1 FROM pg_database WHERE datname='$PG_DATABASE'")" != "1" ]]; then
  "$PG_PREFIX/bin/createdb" -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" \
    -O "$PG_APP_USER" "$PG_DATABASE"
fi

"$PG_PREFIX/bin/psql" -h "$PG_HOST" -p "$PG_PORT" -U "$PG_APP_USER" -d "$PG_DATABASE" -tAc \
  "SELECT current_user || '|' || current_database() || '|' || current_setting('server_version');"
touch "${TMPDIR:-/tmp}/rwa-postgres-bootstrap.ok"
