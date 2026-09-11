#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "${0:A:h}/local-runtime.sh"
require_executable "$NODE_BIN" "Node.js"

NODE_MAJOR="$($NODE_BIN -p 'process.versions.node.split(".")[0]')"
if [[ "$NODE_MAJOR" != "22" ]]; then
  print -u2 "Node.js 22 is required; resolved $NODE_BIN ($($NODE_BIN --version))"
  exit 1
fi

cd "$PROJECT_DIR"
set -a
source .env
set +a

# This script owns the local database endpoint. Keep it aligned with the
# overridable PostgreSQL runtime instead of silently retaining a stale .env URL.
export DATABASE_URL="${RWA_DATABASE_URL:-postgresql://${PG_APP_USER}@${PG_HOST}:${PG_PORT}/${PG_DATABASE}}"

"$NODE_BIN" scripts/migrate.js
# Database integration files share one local PostgreSQL instance. Run files
# serially so the deliberate SSI/connection-kill resilience tests cannot
# inject faults into unrelated acceptance tests. Concurrency is created inside
# the resilience test itself.
"$NODE_BIN" --test --test-concurrency=1
