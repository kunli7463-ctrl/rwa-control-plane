#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "${0:A:h}/local-runtime.sh"
BACKUP_DIR="${1:-$PROJECT_DIR/.local/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="$BACKUP_DIR/${PG_DATABASE}_$STAMP.dump"
PARTIAL_FILE="$BACKUP_FILE.partial"

require_executable "$PG_PREFIX/bin/pg_dump" "PostgreSQL pg_dump"
require_executable "$PG_PREFIX/bin/pg_restore" "PostgreSQL pg_restore"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
cleanup() { rm -f "$PARTIAL_FILE"; }
trap cleanup EXIT INT TERM

"$PG_PREFIX/bin/pg_dump" \
  --host="$PG_HOST" --port="$PG_PORT" --username="$PG_APP_USER" --dbname="$PG_DATABASE" \
  --format=custom --compress=none --no-owner --no-acl --file="$PARTIAL_FILE"
mv "$PARTIAL_FILE" "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"

CHECKSUM="$(shasum -a 256 "$BACKUP_FILE" | awk '{print $1}')"
print "$CHECKSUM  ${BACKUP_FILE:t}" > "$BACKUP_FILE.sha256"
chmod 600 "$BACKUP_FILE.sha256"
"$PG_PREFIX/bin/pg_restore" --list "$BACKUP_FILE" > "$BACKUP_FILE.contents"
chmod 600 "$BACKUP_FILE.contents"

print "$BACKUP_FILE"
print "$CHECKSUM"
