#!/bin/zsh
set -euo pipefail

source "${0:A:h}/local-runtime.sh"
require_executable "$PG_PREFIX/bin/createdb" "PostgreSQL createdb"
require_executable "$PG_PREFIX/bin/dropdb" "PostgreSQL dropdb"
require_executable "$PG_PREFIX/bin/pg_restore" "PostgreSQL pg_restore"
require_executable "$PG_PREFIX/bin/psql" "PostgreSQL psql"
BACKUP_FILE="${1:?usage: verify-local-backup-restore.sh /absolute/path/to/backup.dump}"
[[ "$BACKUP_FILE" = /* && -f "$BACKUP_FILE" ]] || { print -u2 "backup must be an existing absolute path"; exit 1; }
[[ -f "$BACKUP_FILE.sha256" ]] || { print -u2 "checksum sidecar is required"; exit 1; }

cd "${BACKUP_FILE:h}"
shasum -a 256 -c "${BACKUP_FILE:t}.sha256"

TARGET_DB="rwa_restore_verify_$(date -u +%Y%m%d%H%M%S)_$$"
[[ "$TARGET_DB" =~ '^rwa_restore_verify_[0-9]+_[0-9]+$' ]] || { print -u2 "unsafe temporary database name"; exit 1; }

cleanup() {
  "$PG_PREFIX/bin/dropdb" --if-exists --force \
    --host="$PG_HOST" --port="$PG_PORT" --username="$PG_ADMIN_USER" "$TARGET_DB" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"$PG_PREFIX/bin/createdb" --host="$PG_HOST" --port="$PG_PORT" --username="$PG_ADMIN_USER" \
  --owner="$PG_APP_USER" "$TARGET_DB"
"$PG_PREFIX/bin/pg_restore" --exit-on-error --no-owner --no-acl \
  --host="$PG_HOST" --port="$PG_PORT" --username="$PG_APP_USER" --dbname="$TARGET_DB" "$BACKUP_FILE"

RESULT="$($PG_PREFIX/bin/psql --host="$PG_HOST" --port="$PG_PORT" --username="$PG_APP_USER" --dbname="$TARGET_DB" \
  --tuples-only --no-align --set=ON_ERROR_STOP=1 -c \
  "SELECT (SELECT count(*) FROM rwa.schema_migrations) || '|' ||
          (SELECT count(*) FROM rwa.products) || '|' ||
          (SELECT count(*) FROM rwa.transaction_intents) || '|' ||
          (SELECT count(*) FROM rwa.audit_events);")"
print "restore_verified|$TARGET_DB|$RESULT"
