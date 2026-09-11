#!/bin/zsh
set -euo pipefail
PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/local-runtime.sh"
cd "$PROJECT_DIR"
require_executable "$NODE_BIN" "Node.js"
"$NODE_BIN" --test test/monitoring-pack.test.js test/monitoring-notifications.test.js test/outbox-monitor.test.js test/prover-monitor.test.js test/web-telemetry.test.js
PROMTOOL_BIN="${RWA_PROMTOOL_BIN:-$(command -v promtool || true)}"
if [[ -z "$PROMTOOL_BIN" && -x "$PROJECT_DIR/.local-tools/prometheus-3.14.0.darwin-arm64/promtool" ]]; then
  PROMTOOL_BIN="$PROJECT_DIR/.local-tools/prometheus-3.14.0.darwin-arm64/promtool"
fi
if [[ -z "$PROMTOOL_BIN" || ! -x "$PROMTOOL_BIN" ]]; then
  print -u2 "NEEDS_RUNTIME_VERIFICATION: set RWA_PROMTOOL_BIN; no native rules acceptance claimed."
  exit 2
fi
cd deploy/monitoring
"$PROMTOOL_BIN" check rules rwa-alerts.yml
"$PROMTOOL_BIN" test rules alert-tests.yml
print "MONITORING_RULES_ACCEPTANCE_OK (Grafana startup and notification delivery remain separate)"
