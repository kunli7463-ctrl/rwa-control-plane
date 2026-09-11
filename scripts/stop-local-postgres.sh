#!/bin/zsh
set -euo pipefail

source "${0:A:h}/local-runtime.sh"
require_executable "$PG_PREFIX/bin/pg_isready" "PostgreSQL pg_isready"
require_executable "$PG_PREFIX/bin/pg_ctl" "PostgreSQL pg_ctl"

if "$PG_PREFIX/bin/pg_isready" -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1 \
   || "$PG_PREFIX/bin/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
  "$PG_PREFIX/bin/pg_ctl" -D "$PG_DATA" stop -m fast
else
  echo "PostgreSQL is already stopped"
fi
