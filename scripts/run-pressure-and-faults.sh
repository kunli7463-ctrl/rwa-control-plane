#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/local-runtime.sh"
require_executable "$NODE_BIN" "Node.js"

export DATABASE_URL="${DATABASE_URL:-postgresql://${PG_APP_USER}@${PG_HOST}:${PG_PORT}/${PG_DATABASE}}"
export RWA_STRESS_EVENT_COUNT="${RWA_STRESS_EVENT_COUNT:-100}"
export RWA_STRESS_WORKERS="${RWA_STRESS_WORKERS:-6}"

cd "$PROJECT_DIR"
./scripts/start-local-postgres.sh
"$NODE_BIN" --test --test-concurrency=1 \
  test/stress/worker-pressure.test.js \
  test/isolated-prover-client.test.js \
  test/outbox-worker.test.js \
  test/prover-worker.test.js \
  test/integration/postgres-resilience.integration.test.js \
  test/integration/outbox-dispatcher.integration.test.js \
  test/integration/pressure-faults.integration.test.js
print "PRESSURE_AND_FAULT_ACCEPTANCE_OK"

