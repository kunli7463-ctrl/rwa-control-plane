#!/bin/zsh
set -euo pipefail
PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/local-runtime.sh"
cd "$PROJECT_DIR"
require_executable "$NODE_BIN" "Node.js"
export RWA_CIRCOM_BIN="${RWA_CIRCOM_BIN:-$PROJECT_DIR/circom-v2.1.6-build/release/circom}"
require_executable "$RWA_CIRCOM_BIN" "Circom 2.1.6"

# Never restart the host database, publish an image or call an external institution.
./scripts/verify-local-postgres.sh
./scripts/verify-monitoring.sh
"$NODE_BIN" scripts/verify-monitoring-runtime.js
REBUILD_OUTPUT="$("$NODE_BIN" scripts/verify-zk-rebuild.js)"
print -r -- "$REBUILD_OUTPUT"
REBUILD_DIR="${REBUILD_OUTPUT#ZK rebuild evidence: }"
if [[ "$REBUILD_DIR" != "$PROJECT_DIR/.local/zk-rebuild-"* || ! -f "$REBUILD_DIR/report.json" ]]; then
  print -u2 "Invalid rebuild evidence path"
  exit 1
fi
"$NODE_BIN" scripts/verify-zk-candidate-matrix.js "$REBUILD_DIR/first"
# Registry failures or outstanding advisories stop the chain, never become a green release.
"$NODE_BIN" scripts/build-release-evidence.js
print "LOCAL_INTERNAL_CHECKS_PASSED_NOT_PRODUCTION_APPROVAL"
