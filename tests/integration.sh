#!/usr/bin/env bash
# End-to-end test against a real nginx container. Requires Docker.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${N2RPG_TEST_IMAGE:-n2rpg-test:local}
NAME="n2rpg-test-$$"
OUT=$(mktemp)

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -f "$OUT"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 0; }

echo "building $IMAGE"
docker build -q -f "$ROOT/tests/docker/Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null

docker run -d --name "$NAME" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
    if docker exec "$NAME" nginx -t >/dev/null 2>&1; then break; fi
    sleep 0.5
done

set +e
docker exec "$NAME" n2rpg --nginx-version 1.31.9 --no-color --format json --fail-on high > "$OUT"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
    echo "integration: n2rpg exited $RC"
    cat "$OUT"
    exit 1
fi

jq -e '.target.mode == "live"' "$OUT" >/dev/null || { echo "expected live mode"; cat "$OUT"; exit 1; }
jq -e '[.findings[] | select(.id=="H2-008" and .status=="pass")] | length >= 1' "$OUT" >/dev/null \
    || { echo "expected ALPN h2 pass"; cat "$OUT"; exit 1; }
jq -e '[.findings[] | select(.id=="ROOT-001" and .status=="pass")] | length >= 1' "$OUT" >/dev/null \
    || { echo "expected non-root workers"; cat "$OUT"; exit 1; }
jq -e '.summary.critical == 0 and .summary.high == 0' "$OUT" >/dev/null \
    || { echo "unexpected critical/high findings"; cat "$OUT"; exit 1; }

echo "integration: ok"
