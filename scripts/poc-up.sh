#!/bin/sh
# Start the local PoC stack: PostgreSQL, migrations, web demo and outbox worker.
#
# Works with either Compose front end: the `docker compose` plugin (V2) or the
# standalone `docker-compose` binary. POSIX sh on purpose — reviewers run this
# on Linux and macOS, with or without Docker Desktop.
#
# Any extra arguments are passed to `up`, e.g. `./scripts/poc-up.sh -d`.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$root/deploy/compose/postgres-poc.yaml"

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose -f "$compose_file" "$@"; }
  front_end="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose -f "$compose_file" "$@"; }
  front_end="docker-compose"
else
  echo "Docker Compose is required: install Docker Desktop, the docker compose plugin, or docker-compose." >&2
  exit 1
fi

echo "Using $front_end with $compose_file"
echo "The web demo will be at http://127.0.0.1:${RWA_POC_WEB_PORT:-8765} once health checks pass."
compose up --build "$@"
