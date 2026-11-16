#!/usr/bin/env bash
# Fixture-based regression tests. No root and no network required.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$ROOT/nginx2root.sh"
FIX="$ROOT/tests/fixtures"
PASS=0
FAIL=0
JSON=""
TEXT=""
RC=0

command -v jq >/dev/null 2>&1 || { echo "jq is required for tests"; exit 2; }

ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

run_json() { JSON=$("$BIN" --format json "$@" 2>/dev/null); RC=$?; }
run_text() { TEXT=$("$BIN" "$@" 2>/dev/null); RC=$?; }

assert_eq() {
    local desc=$1 exp=$2 act=$3
    if [[ $act == "$exp" ]]; then ok "$desc"; else bad "$desc (expected $exp, got $act)"; fi
}
assert_has() {
    local desc=$1 id=$2 status=${3:-}
    if [[ -n $status ]]; then
        if jq -e --arg id "$id" --arg st "$status" \
            '[.findings[] | select(.id==$id and .status==$st)] | length > 0' <<< "$JSON" >/dev/null; then
            ok "$desc"
        else
            bad "$desc (missing $id/$status)"
        fi
    else
        if jq -e --arg id "$id" '[.findings[] | select(.id==$id)] | length > 0' <<< "$JSON" >/dev/null; then
            ok "$desc"
        else
            bad "$desc (missing $id)"
        fi
    fi
}
assert_not_has() {
    local desc=$1 id=$2
    if jq -e --arg id "$id" '[.findings[] | select(.id==$id)] | length == 0' <<< "$JSON" >/dev/null; then
        ok "$desc"
    else
        bad "$desc (unexpected $id)"
    fi
}
assert_jq() {
    local desc=$1 expr=$2
    if jq -e "$expr" <<< "$JSON" >/dev/null; then ok "$desc"; else bad "$desc"; fi
}
assert_contains() {
    local desc=$1 needle=$2
    if [[ $TEXT == *"$needle"* ]]; then ok "$desc"; else bad "$desc (missing '$needle')"; fi
}
assert_not_contains() {
    local desc=$1 needle=$2
    if [[ $TEXT != *"$needle"* ]]; then ok "$desc"; else bad "$desc (found '$needle')"; fi
}

# --- basic CLI -------------------------------------------------------------
run_text --version
assert_eq "--version exit" 0 "$RC"
assert_contains "--version output" "nginx2root 1.0.0"

run_text --self-test
assert_eq "--self-test exit" 0 "$RC"

run_text --help
assert_eq "--help exit" 0 "$RC"
assert_contains "--help usage" "Usage:"

run_text --list-checks
assert_eq "--list-checks exit" 0 "$RC"
assert_contains "--list-checks H2-001" "H2-001"
assert_contains "--list-checks CVE table" "CVE-2026-123007"

run_text --list-cves
assert_eq "--list-cves exit" 0 "$RC"
assert_contains "--list-cves row" "CVE-2026-123007"

run_text --definitely-not-an-option
assert_eq "unknown option exit" 2 "$RC"

run_text --dump /nonexistent/nginx.conf
assert_eq "missing dump exit" 3 "$RC"

# --- insecure fixture ------------------------------------------------------
run_json --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --fail-on high
assert_eq "insecure exit" 1 "$RC"
for id in ROOT-002 H2-002 H2-006 TLS-001 TLS-002 CFG-003 CFG-004 CFG-007 CFG-008 CFG-011; do
    assert_has "insecure has $id" "$id"
done
assert_has "insecure critical CVE" "CVE-2026-123007" "fail"
assert_has "insecure alias is high" "CFG-004" "fail"
assert_has "insecure dump skips perms" "ROOT-004" "skip"
assert_not_has "insecure is not h2c" "H2-003"
assert_jq "insecure summary critical" '.summary.critical >= 1'
assert_jq "insecure json valid" '.tool == "nginx2root"'

# --- secure fixture --------------------------------------------------------
run_json --dump "$FIX/secure.conf" --nginx-version 1.31.9 --no-live --no-color --fail-on high
assert_eq "secure exit" 0 "$RC"
assert_has "secure h2 enabled" "H2-001" "pass"
assert_has "secure stub_status restricted" "CFG-003" "pass"
assert_has "secure default_server" "CFG-013" "pass"
assert_has "secure dotfiles blocked" "CFG-006" "pass"
assert_not_has "secure has no http2 CVE" "CVE-2026-123007"
assert_jq "secure no critical/high" '.summary.critical == 0 and .summary.high == 0'

# --- version branch logic --------------------------------------------------
run_json --dump "$FIX/secure.conf" --nginx-version 1.31.8 --no-live --no-color --fail-on high
assert_eq "vulnerable version exit" 1 "$RC"
assert_has "vulnerable 1.31.8" "CVE-2026-123007" "fail"

run_json --dump "$FIX/secure.conf" --nginx-version 1.30.7 --no-live --no-color --fail-on high
assert_eq "fixed stable branch exit" 0 "$RC"
assert_not_has "fixed 1.30.7" "CVE-2026-123007"

# --- h2c and edge fixtures -------------------------------------------------
run_json --dump "$FIX/h2c.conf" --nginx-version 1.31.9 --no-live --no-color --fail-on high
assert_eq "h2c exit" 0 "$RC"
assert_has "h2c detected" "H2-003" "warn"

run_json --dump "$FIX/edge.conf" --nginx-version 1.31.9 --no-live --no-color --fail-on high
assert_eq "edge exit" 1 "$RC"
for id in ROOT-006 CFG-007 CFG-011 CFG-014 CFG-017 CFG-018 CFG-008 TLS-010; do
    assert_has "edge has $id" "$id"
done

# --- filters and thresholds ------------------------------------------------
run_json --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --only H2 --fail-on high
assert_has "only H2 keeps H2-006" "H2-006"
assert_not_has "only H2 drops ROOT-002" "ROOT-002"

run_json --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --exclude H2 --fail-on high
assert_not_has "exclude H2 drops H2-006" "H2-006"
assert_has "exclude H2 keeps ROOT-002" "ROOT-002"

run_json --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --fail-on none
assert_eq "fail-on none exit" 0 "$RC"

run_json --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --fail-on critical
assert_eq "fail-on critical exit" 1 "$RC"

run_text --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --min-severity critical
assert_not_contains "min-severity critical hides WARN" "WARN"

run_text --dump "$FIX/insecure.conf" --nginx-version 1.25.2 --no-live --no-color --quiet
assert_not_contains "quiet hides summary" "Summary:"

run_text --dump "$FIX/secure.conf" --nginx-version 1.31.9 --no-live --no-color --verbose
assert_contains "verbose shows passes" " ok "
assert_contains "verbose shows skips" "skip"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
