#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"

cd "$PROJECT_DIR"
./scripts/stop-local-postgres.sh
./scripts/start-local-postgres.sh
./scripts/verify-local-postgres.sh

LATEST_MIGRATION="$(find db/migrations -maxdepth 1 -name '*.sql' -print | sort | tail -n 1)"
print "FINAL_ACCEPTANCE_OK"
print "migration=${LATEST_MIGRATION:t}"
print "product_boundary=CONFIDENTIAL_NOTE_LEDGER"
print "legal_register_bridge=EXTERNAL_REQUIRED"
print "note_root_and_effects_bridge=EXTERNAL_REQUIRED"
