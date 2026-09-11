#!/bin/zsh

# Shared local-development runtime discovery. Every value is overridable so
# acceptance, backup and restore do not depend on one developer's home path.
if [[ -n "${RWA_RUNTIME_ROOT:-}" ]]; then
  RWA_LOCAL_RUNTIME_ROOT="$RWA_RUNTIME_ROOT"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  RWA_LOCAL_RUNTIME_ROOT="${HOME}/Library/Application Support/RWADev"
else
  RWA_LOCAL_RUNTIME_ROOT="${XDG_DATA_HOME:-${HOME}/.local/share}/RWADev"
fi

PG_PREFIX="${RWA_PG_PREFIX:-$RWA_LOCAL_RUNTIME_ROOT/postgresql-16.15}"
PG_DATA="${RWA_PG_DATA:-$RWA_LOCAL_RUNTIME_ROOT/pgdata-16}"
PG_HOST="${RWA_PG_HOST:-127.0.0.1}"
PG_PORT="${RWA_PG_PORT:-5432}"
PG_ADMIN_USER="${RWA_PG_ADMIN_USER:-rwa_admin}"
PG_APP_USER="${RWA_PG_APP_USER:-rwa_app}"
PG_DATABASE="${RWA_PG_DATABASE:-rwa_control_plane}"

if [[ -n "${RWA_NODE_BIN:-}" ]]; then
  NODE_BIN="$RWA_NODE_BIN"
elif [[ -x "$RWA_LOCAL_RUNTIME_ROOT/node22/bin/node" ]]; then
  NODE_BIN="$RWA_LOCAL_RUNTIME_ROOT/node22/bin/node"
else
  NODE_BIN="$(command -v node 2>/dev/null || true)"
fi

require_executable() {
  local executable="$1"
  local description="$2"
  if [[ -z "$executable" || ! -x "$executable" ]]; then
    print -u2 "$description is not executable: ${executable:-<not found>}"
    return 1
  fi
}

require_identifier() {
  local identifier="$1"
  local description="$2"
  if [[ ! "$identifier" =~ '^[A-Za-z_][A-Za-z0-9_]*$' ]]; then
    print -u2 "$description must be a PostgreSQL identifier: $identifier"
    return 1
  fi
}
