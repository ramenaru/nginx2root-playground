#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

compose=()
if docker compose version >/dev/null 2>&1; then
    compose=(docker compose -f lab/docker-compose.yml)
elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose -f lab/docker-compose.yml)
else
    echo "docker compose is required" >&2
    exit 1
fi

mkdir -p lab/results

for role in vulnerable hardened; do
    echo "== ${role} =="
    "${compose[@]}" exec -T "$role" nginx2root --no-color --fail-on none
    "${compose[@]}" exec -T "$role" nginx2root --format json --fail-on none > "lab/results/${role}.json"
    echo
done

echo "json written to lab/results/"
