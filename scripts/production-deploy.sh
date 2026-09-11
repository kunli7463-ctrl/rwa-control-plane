#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
COMPOSE_FILE="$PROJECT_DIR/deploy/compose/production.example.yaml"

: "${RWA_IMAGE:?RWA_IMAGE must be an immutable registry reference ending in @sha256:<64 lowercase hex>}"
: "${RWA_PRODUCTION_ENV:?RWA_PRODUCTION_ENV must point to the populated production env file}"
: "${RWA_PROVIDER_DIR:?RWA_PROVIDER_DIR must point to reviewed provider modules}"
: "${RWA_ZK_ARTIFACT_DIR:?RWA_ZK_ARTIFACT_DIR must point to approved Groth16 artifacts}"

if [[ ! "$RWA_IMAGE" =~ '@sha256:[0-9a-f]{64}$' ]]; then
  print -u2 "RWA_IMAGE must be pinned by a lowercase sha256 digest"
  exit 2
fi
for required_path in "$RWA_PRODUCTION_ENV" "$RWA_PROVIDER_DIR" "$RWA_ZK_ARTIFACT_DIR"; do
  if [[ "$required_path" != /* || ! -e "$required_path" ]]; then
    print -u2 "deployment path must be absolute and exist: $required_path"
    exit 2
  fi
done
if ! command -v docker >/dev/null 2>&1; then
  print -u2 "Docker with Compose v2 is required"
  exit 2
fi

cd "$PROJECT_DIR"
docker compose -f "$COMPOSE_FILE" config --quiet
docker compose -f "$COMPOSE_FILE" run --rm preflight
docker compose -f "$COMPOSE_FILE" run --rm artifact-check
docker compose -f "$COMPOSE_FILE" run --rm migrate
docker compose -f "$COMPOSE_FILE" up -d --wait --wait-timeout "${RWA_DEPLOY_WAIT_SECONDS:-180}" \
  web outbox-worker prover-worker
docker compose -f "$COMPOSE_FILE" ps
print "PRODUCTION_DEPLOYMENT_HEALTHY"

