#!/bin/zsh
set -euo pipefail
PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/local-runtime.sh"
cd "$PROJECT_DIR"
require_executable "$NODE_BIN" "Node.js 22"
export RWA_CHROME_BIN="${RWA_CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
export RWA_PLAYWRIGHT_MODULE="${RWA_PLAYWRIGHT_MODULE:-$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright}"
require_executable "$RWA_CHROME_BIN" "Chrome for isolated visual acceptance"
if [[ ! -d "$RWA_PLAYWRIGHT_MODULE" ]]; then
  print -u2 "Set RWA_PLAYWRIGHT_MODULE to the installed Playwright package directory"
  exit 2
fi
# Run from the owning host terminal. Fresh browser profile only; no existing user tabs/profiles.
# The running local PostgreSQL instance is used without a forced restart.
zsh scripts/verify-internal.sh
print "HOST_LOCAL_CLOSEOUT_PASSED_NOT_PRODUCTION_OR_INDEPENDENT_AUDIT_APPROVAL"
