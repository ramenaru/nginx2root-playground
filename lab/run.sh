#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

compose=()
if docker compose version >/dev/null 2>&1; then
    compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose)
else
    echo "docker compose is required" >&2
    exit 1
fi

"${compose[@]}" up -d --build

echo
echo "vulnerable"
echo "  http  http://localhost:8080"
echo "  https https://localhost:8443"
echo "  h2c   http://localhost:8082"
echo "hardened"
echo "  http  http://localhost:8081"
echo "  https https://localhost:8444"
echo
echo "run ./lab/audit.sh to audit both targets"
