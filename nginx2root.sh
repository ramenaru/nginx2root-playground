#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# nginx2root - audit nginx for HTTP/2 weaknesses and nginx -> root flaws.
#
# Defensive tool. It reads configuration, inspects local permissions and
# optionally probes the local TLS listener. It never writes to nginx and never
# attempts exploitation.

set -uo pipefail

VERSION="1.0.0"
PROG="nginx2root"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OPT_CONFIG=""
OPT_DUMP=""
OPT_LIVE=-1                 # -1 = auto, 0 = off, 1 = on
OPT_SUDO=1
OPT_HOST="127.0.0.1"
OPT_PORT=443
OPT_TIMEOUT=5
OPT_ONLY=""
OPT_EXCLUDE=""
OPT_FAIL_ON="high"
OPT_MIN_SEV="info"
OPT_FORMAT="text"
OPT_NO_COLOR=0
OPT_QUIET=0
OPT_VERBOSE=0
OPT_NGINX_VERSION=""
OPT_MAX_DOMAINS=25

NGINX_BIN=""
NGINX_VERSION=""
NGINX_ERR=""
NGINX_TEST_OK=-1
CONFIG_MAIN=""
NGINX_PREFIX=""
DUMP_FILE=""
MODE=""
LIVE=0
PROBE_HOST="$OPT_HOST"
PROBE_PORT="$OPT_PORT"

EUID_IS_ROOT=0
[[ ${EUID:-$(id -u)} -eq 0 ]] && EUID_IS_ROOT=1

N2R_TMP=""
cleanup() {
    [[ -n ${N2R_TMP:-} && -d ${N2R_TMP:-} ]] && rm -rf -- "$N2R_TMP"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""

init_colors() {
    if [[ $OPT_NO_COLOR -eq 0 && -t 1 && -z ${NO_COLOR:-} ]]; then
        C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
        C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
        C_CYAN=$'\033[1;36m'
    fi
}

say() { printf '%s\n' "$*"; }
err() { printf '%s: %s\n' "$PROG" "$*" >&2; }

die() {
    local code=$1; shift
    err "$*"
    exit "$code"
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'EOF'
nginx2root - audit nginx for HTTP/2 weaknesses and nginx -> root flaws

Usage:
  nginx2root [options]

Config source:
  -c, --config PATH       nginx config to test (passed to nginx -c)
  -T, --dump PATH         read an existing `nginx -T` dump (offline mode)
      --nginx-version V   nginx version for offline/CVE checks (e.g. 1.31.9)

Checks:
      --no-live           skip TLS/ALPN/HTTP probes
      --live              force live probes even with --dump
  -H, --host HOST         host to probe (default 127.0.0.1)
  -p, --port PORT         TLS port to probe (default 443)
      --timeout SEC       probe timeout (default 5)
      --max-domains N     max server_names to probe (default 25)
      --no-sudo           never try sudo
      --only LIST         run only these IDs/prefixes (comma separated)
      --exclude LIST      skip these IDs/prefixes (comma separated)

Output:
      --format FMT        text or json (default text)
      --json              alias for --format json
      --min-severity LV   only print findings >= LV (default info)
      --fail-on LV        exit 1 on findings >= LV: critical|high|medium|low|info|none
                          (default high)
      --no-color          disable ANSI colour
  -q, --quiet             only print actionable findings
  -v, --verbose           show passing and skipped checks too

Other:
      --list-checks       list all checks and exit
      --list-cves         list the built-in advisory table and exit
      --self-test         run internal unit tests and exit
  -V, --version           print version
  -h, --help              this help

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage or environment error
  3  could not read/parse an nginx configuration

Examples:
  sudo nginx2root
  sudo nginx2root --fail-on medium --format json
  nginx2root --dump nginx-T.txt --nginx-version 1.31.9 --no-live
  sudo nginx2root --only H2,TLS --host 127.0.0.1 --port 443
EOF
}

sev_rank() {
    case $1 in
        critical) printf '4' ;;
        high)     printf '3' ;;
        medium)   printf '2' ;;
        low)      printf '1' ;;
        info)     printf '0' ;;
        none)     printf '99' ;;
        *)        printf '0' ;;
    esac
}

sev_label() {
    case $1 in
        critical) printf 'CRIT' ;;
        high)     printf 'HIGH' ;;
        medium)   printf 'MED' ;;
        low)      printf 'LOW' ;;
        *)        printf 'INFO' ;;
    esac
}

sev_color() {
    case $1 in
        critical) printf '%s' "$C_RED" ;;
        high)     printf '%s' "$C_RED" ;;
        medium)   printf '%s' "$C_YELLOW" ;;
        low)      printf '%s' "$C_CYAN" ;;
        *)        printf '%s' "$C_DIM" ;;
    esac
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//$'\x1f'/}
    printf '%s' "$s"
}

one_line() { printf '%s' "$1" | tr '\n\r\t' '   '; }

# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------
ver_cmp() {
    local a=${1#nginx/} b=${2#nginx/}
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 _ <<< "$a"
    IFS=. read -r b1 b2 b3 _ <<< "$b"
    a1=${a1:-0}; a2=${a2:-0}; a3=${a3:-0}
    b1=${b1:-0}; b2=${b2:-0}; b3=${b3:-0}
    a1=${a1//[!0-9]/}; a2=${a2//[!0-9]/}; a3=${a3//[!0-9]/}
    b1=${b1//[!0-9]/}; b2=${b2//[!0-9]/}; b3=${b3//[!0-9]/}
    a1=${a1:-0}; a2=${a2:-0}; a3=${a3:-0}
    b1=${b1:-0}; b2=${b2:-0}; b3=${b3:-0}
    if (( 10#$a1 != 10#$b1 )); then (( 10#$a1 > 10#$b1 )) && VCMP=1 || VCMP=-1; return
    fi
    if (( 10#$a2 != 10#$b2 )); then (( 10#$a2 > 10#$b2 )) && VCMP=1 || VCMP=-1; return
    fi
    if (( 10#$a3 != 10#$b3 )); then (( 10#$a3 > 10#$b3 )) && VCMP=1 || VCMP=-1; return
    fi
    VCMP=0
}

ver_ge() { ver_cmp "$1" "$2"; (( VCMP >= 0 )); }
ver_gt() { ver_cmp "$1" "$2"; (( VCMP > 0 )); }

# version_fixed VERSION "fix1,fix2"
# Safe if version is >= the highest fix, or on the same major.minor branch as
# any fix with patch >= that fix. Handles stable/mainline branches such as
# "1.31.9,1.30.7" without treating 1.31.0 as fixed by 1.30.7.
version_fixed() {
    local ver=$1 fixes=$2 fix maxfix="" v1 v2 v3 f1 f2 f3
    local IFS=,
    for fix in $fixes; do
        fix=${fix// /}
        [[ -z $fix ]] && continue
        if [[ -z $maxfix ]]; then maxfix=$fix
        else ver_cmp "$fix" "$maxfix"; (( VCMP > 0 )) && maxfix=$fix
        fi
        IFS=. read -r v1 v2 v3 _ <<< "$ver"
        IFS=. read -r f1 f2 f3 _ <<< "$fix"
        v1=${v1//[!0-9]/}; v2=${v2//[!0-9]/}; v3=${v3//[!0-9]/}
        f1=${f1//[!0-9]/}; f2=${f2//[!0-9]/}; f3=${f3//[!0-9]/}
        v1=${v1:-0}; v2=${v2:-0}; v3=${v3:-0}
        f1=${f1:-0}; f2=${f2:-0}; f3=${f3:-0}
        if (( 10#$v1 == 10#$f1 && 10#$v2 == 10#$f2 && 10#$v3 >= 10#$f3 )); then
            return 0
        fi
    done
    [[ -n $maxfix ]] && ver_ge "$ver" "$maxfix" && return 0
    return 1
}

version_vulnerable() {
    local ver=$1 min=$2 max=$3 fixes=$4
    [[ -z $ver ]] && return 1
    ver_ge "$ver" "$min" || return 1
    if [[ -n $max ]] && ver_gt "$ver" "$max"; then return 1; fi
    version_fixed "$ver" "$fixes" && return 1
    return 0
}

# ---------------------------------------------------------------------------
# Findings and check registry
# ---------------------------------------------------------------------------
declare -a F_ID=() F_SEV=() F_ST=() F_TITLE=() F_DETAIL=() F_FIX=() F_REF=()
declare -A CHECK_SEV=() CHECK_TITLE=()

register_check() {
    CHECK_SEV[$1]=$2
    CHECK_TITLE[$1]=$3
}

check_enabled() {
    local id=$1
    if [[ -n $OPT_ONLY ]] && ! id_match "$id" "$OPT_ONLY"; then return 1; fi
    if [[ -n $OPT_EXCLUDE ]] && id_match "$id" "$OPT_EXCLUDE"; then return 1; fi
    return 0
}

id_match() {
    local id=$1 list=$2 item
    local IFS=,
    for item in $list; do
        item=${item// /}
        [[ -z $item ]] && continue
        [[ $id == "$item" || $id == "$item"* ]] && return 0
    done
    return 1
}

emit() {
    local id=$1 status=$2 detail=${3:-} fix=${4:-} ref=${5:-}
    check_enabled "$id" || return 0
    local sev=${CHECK_SEV[$id]:-info}
    F_ID+=("$id")
    F_SEV+=("$sev")
    F_ST+=("$status")
    F_TITLE+=("${CHECK_TITLE[$id]:-$id}")
    F_DETAIL+=("$detail")
    F_FIX+=("$fix")
    F_REF+=("$ref")
}

register_all_checks() {
    # Environment
    register_check ENV-001 info     "nginx binary located"
    register_check ENV-002 info     "nginx version detected"
    register_check ENV-003 critical "nginx configuration syntax"
    register_check ENV-004 info     "nginx runtime processes"
    register_check ENV-005 info     "audit privilege level"

    # HTTP/2
    register_check H2-001 info     "HTTP/2 enabled"
    register_check H2-002 low      "deprecated listen ... http2 syntax"
    register_check H2-003 medium   "HTTP/2 over cleartext (h2c)"
    register_check H2-004 medium   "HTTP/2 concurrent stream limit"
    register_check H2-005 medium   "HTTP/2 keepalive_requests limit"
    register_check H2-006 high     "HTTP/2 Rapid Reset exposure"
    register_check H2-007 info     "http2_push directive"
    register_check H2-008 high     "HTTP/2 ALPN negotiation"
    register_check H2-009 info     "unexpected HTTP/2 ALPN"
    register_check H2-010 low      "invalid http2 directive value"

    # TLS
    register_check TLS-001 high     "legacy TLS protocols enabled"
    register_check TLS-002 high     "weak TLS ciphers enabled"
    register_check TLS-003 low      "server cipher preference disabled"
    register_check TLS-004 medium   "HSTS header missing"
    register_check TLS-005 low      "HSTS max-age too short"
    register_check TLS-006 high     "certificate expired or expiring"
    register_check TLS-007 critical "private key permissions"
    register_check TLS-008 info     "self-signed certificate"
    register_check TLS-009 low      "OCSP stapling disabled"
    register_check TLS-010 medium   "OCSP stapling without resolver"
    register_check TLS-011 medium   "optional_no_ca client verification"
    register_check TLS-012 high     "legacy TLS accepted (live)"
    register_check TLS-013 low      "TLS session cache disabled"
    register_check TLS-014 medium   "live certificate hostname mismatch"
    register_check TLS-015 high     "TLS listener without certificate"
    register_check TLS-016 low      "HSTS header missing always"
    register_check TLS-017 medium   "live certificate expiring"

    # nginx -> root
    register_check ROOT-001 critical "worker processes run as root"
    register_check ROOT-002 critical "user root directive"
    register_check ROOT-003 critical "master_process off while root"
    register_check ROOT-004 critical "writable nginx configuration"
    register_check ROOT-005 critical "writable nginx configuration directory"
    register_check ROOT-006 high     "include from risky path"
    register_check ROOT-007 critical "writable nginx binary"
    register_check ROOT-008 high     "writable web root"
    register_check ROOT-009 high     "pid file in writable directory"
    register_check ROOT-010 high     "excessive process capabilities"
    register_check ROOT-011 low      "systemd hardening missing"
    register_check ROOT-012 high     "writable systemd ExecStartPre"
    register_check ROOT-013 low      "mandatory access control disabled"
    register_check ROOT-014 low      "worker user has a login shell"
    register_check ROOT-015 medium   "world-readable password file"
    register_check ROOT-016 info     "env directive exposes variables"

    # Config flaws
    register_check CFG-001 low      "server_tokens enabled"
    register_check CFG-002 medium   "directory listing enabled"
    register_check CFG-003 high     "stub_status exposed"
    register_check CFG-004 high     "alias traversal"
    register_check CFG-005 medium   "merge_slashes disabled"
    register_check CFG-006 medium   "dotfiles may be served"
    register_check CFG-007 high     "WebDAV write methods without auth"
    register_check CFG-008 medium   "proxy_pass with variable"
    register_check CFG-009 low      "X-Content-Type-Options missing"
    register_check CFG-010 info     "X-Frame-Options/CSP missing"
    register_check CFG-011 high     "sensitive path exposed via root/alias"
    register_check CFG-012 high     "port 443 without TLS"
    register_check CFG-013 info     "no default_server"
    register_check CFG-014 low      "proxy_pass inside if"
    register_check CFG-015 info     "access log disabled"
    register_check CFG-016 medium   "unlimited request body"
    register_check CFG-017 low      "underscores_in_headers enabled"
    register_check CFG-018 low      "ignore_invalid_headers disabled"
    register_check CFG-019 medium   "redirect to plaintext HTTP"
    register_check CFG-020 low      "no rate limiting"
    register_check CFG-021 info     "catch-all server_name"
    register_check CFG-022 low      "excessive slowloris timeouts"
    register_check CFG-023 low      "oversized header buffers"
    register_check CFG-025 medium   "dynamic proxy_pass without resolver"

    # Network
    register_check NET-001 info   "listeners on 80/443"
    register_check NET-002 info   "nginx listener process"
    register_check NET-003 info   "non-nginx process on 80/443"
    register_check NET-004 low    "Server header reveals version"
    register_check NET-005 info   "IPv6 listener"
    register_check NET-006 info   "live probes skipped"
}

# ---------------------------------------------------------------------------
# Config acquisition
# ---------------------------------------------------------------------------
find_nginx() {
    local c
    if [[ -n ${NGINX_BIN_OVERRIDE:-} && -x ${NGINX_BIN_OVERRIDE:-} ]]; then
        NGINX_BIN=$NGINX_BIN_OVERRIDE
        return 0
    fi
    for c in nginx /usr/sbin/nginx /usr/local/sbin/nginx \
             /usr/local/nginx/sbin/nginx /opt/nginx/sbin/nginx; do
        if command -v "$c" >/dev/null 2>&1; then
            NGINX_BIN=$(command -v "$c")
            return 0
        fi
        if [[ -x $c ]]; then
            NGINX_BIN=$c
            return 0
        fi
    done
    return 1
}

find_default_config() {
    local c
    for c in "$OPT_CONFIG" /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf \
             /usr/local/etc/nginx/nginx.conf /opt/homebrew/etc/nginx/nginx.conf; do
        [[ -n $c && -r $c ]] && { printf '%s' "$c"; return 0; }
    done
    return 1
}

declare -A SEEN_CONF=()
collect_conf() {
    local file=$1 real line inc dir f
    real=$(realpath -m -- "$file" 2>/dev/null || printf '%s' "$file")
    [[ -n ${SEEN_CONF[$real]:-} ]] && return 0
    SEEN_CONF[$real]=1
    if [[ ! -r $file ]]; then
        printf '# unreadable: %s\n' "$file"
        return 0
    fi
    printf '# configuration file %s:\n' "$file"
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^[[:space:]]*include[[:space:]]+([^;]+)\; ]]; then
            inc=${BASH_REMATCH[1]}
            inc=${inc%\"}; inc=${inc#\"}; inc=${inc%\'}; inc=${inc#\'}
            dir=$(dirname -- "$file")
            [[ $inc != /* ]] && inc="$dir/$inc"
            shopt -s nullglob
            for f in $inc; do
                collect_conf "$f"
            done
            shopt -u nullglob
        else
            printf '%s\n' "$line"
        fi
    done < "$file"
}

detect_version() {
    [[ -n $OPT_NGINX_VERSION ]] && { NGINX_VERSION=$OPT_NGINX_VERSION; return 0; }
    [[ -n $NGINX_BIN ]] || return 1
    local v
    v=$("$NGINX_BIN" -v 2>&1) || true
    if [[ $v =~ nginx/([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        NGINX_VERSION=${BASH_REMATCH[1]}
        return 0
    fi
    return 1
}

acquire_config() {
    if [[ -n $OPT_DUMP ]]; then
        [[ -r $OPT_DUMP ]] || die 3 "cannot read config dump: $OPT_DUMP"
        DUMP_FILE=$OPT_DUMP
        MODE="offline (dump)"
        local header_main
        header_main=$(awk '/^# configuration file /{sub(/^# configuration file /,""); sub(/:$/,""); print; exit}' "$DUMP_FILE")
        if [[ -n $header_main ]]; then
            CONFIG_MAIN=$header_main
            NGINX_PREFIX=$(dirname -- "$CONFIG_MAIN")
        else
            CONFIG_MAIN=$OPT_DUMP
            NGINX_PREFIX="/etc/nginx"
        fi
        [[ $OPT_LIVE -eq -1 ]] && OPT_LIVE=0
        return 0
    fi

    find_nginx || true
    detect_version || true

    if [[ -n $NGINX_BIN ]]; then
        local args=(-T) err="$N2R_TMP/nginx.err" out="" rc=0
        [[ -n $OPT_CONFIG ]] && args+=(-c "$OPT_CONFIG")
        out=$("$NGINX_BIN" "${args[@]}" 2>"$err") || rc=$?
        if (( rc != 0 )) && [[ $EUID_IS_ROOT -eq 0 && $OPT_SUDO -eq 1 ]] && has_cmd sudo; then
            if sudo -n true 2>/dev/null; then
                out=$(sudo -n "$NGINX_BIN" "${args[@]}" 2>"$err") || rc=$?
            fi
        fi
        NGINX_ERR=$(one_line "$(cat "$err" 2>/dev/null || true)")
        if (( rc == 0 )) && [[ -n $out ]]; then
            printf '%s\n' "$out" > "$N2R_TMP/dump.conf"
            DUMP_FILE="$N2R_TMP/dump.conf"
            NGINX_TEST_OK=1
            MODE="live"
            CONFIG_MAIN=$(awk '/^# configuration file /{sub(/^# configuration file /,""); sub(/:$/,""); print; exit}' "$DUMP_FILE")
            [[ -z $CONFIG_MAIN ]] && CONFIG_MAIN=${OPT_CONFIG:-/etc/nginx/nginx.conf}
            NGINX_PREFIX=$(dirname -- "$CONFIG_MAIN")
            [[ $OPT_LIVE -eq -1 ]] && OPT_LIVE=1
            return 0
        fi
        if [[ $NGINX_ERR == *"Permission denied"* || $NGINX_ERR == *"cannot open"* || $NGINX_ERR == *"cannot load certificate"* ]]; then
            NGINX_TEST_OK=-1
        else
            NGINX_TEST_OK=0
        fi
        [[ -n $out ]] && printf '%s\n' "$out" > "$N2R_TMP/dump.conf.partial"
    fi

    # Fallback: read the config tree directly (works unprivileged for 0644 files).
    local main=""
    main=$(find_default_config || true)
    [[ -z $main ]] && die 3 "could not find an nginx configuration (try --config or --dump)"
    CONFIG_MAIN=$main
    NGINX_PREFIX=$(dirname -- "$main")
    DUMP_FILE="$N2R_TMP/dump.conf"
    if [[ -s "$N2R_TMP/dump.conf.partial" ]]; then
        cp -- "$N2R_TMP/dump.conf.partial" "$DUMP_FILE"
    else
        collect_conf "$main" > "$DUMP_FILE"
    fi
    MODE="offline (direct read)"
    [[ $OPT_LIVE -eq -1 ]] && OPT_LIVE=0
    return 0
}

# ---------------------------------------------------------------------------
# Configuration parser
# ---------------------------------------------------------------------------
AWK_FILE=""
setup_parser() {
    AWK_FILE="$N2R_TMP/parse.awk"
    cat > "$AWK_FILE" <<'AWK_EOF'
BEGIN {
    depth=0; sid=0; lid=0; ctxstr[0]="main"; sidat[0]=0; lidat[0]=0
    file=initfile; lineno=0; buf=""; q=""; stmtline=0; quant=0
}
function trim(s) { sub(/^[ \t\r]+/,"",s); sub(/[ \t\r]+$/,"",s); return s }
function emit(opens,   t,dir,args) {
    t=trim(buf); buf=""
    if (t=="") return
    if (match(t, /^[^ \t]+/)) {
        dir=substr(t,1,RLENGTH)
        args=trim(substr(t,RLENGTH+1))
    } else { dir=t; args="" }
    gsub(/\037/,"",dir); gsub(/\037/,"",args)
    printf "%d\037%d\037%d\037%s\037%s\037%s\037%s\037%d\037%d\n", \
        depth, sidat[depth], lidat[depth], ctxstr[depth], dir, args, file, stmtline, opens
}
function push_block(dir,args,   name) {
    name=dir
    if (args!="") name=name " " args
    depth++
    if (depth==1) ctxstr[depth]=name
    else ctxstr[depth]=ctxstr[depth-1] ">" name
    sidat[depth]=sidat[depth-1]
    lidat[depth]=lidat[depth-1]
    if (dir=="server" && depth==2 && ctxstr[1]=="http") {
        sid++; sidat[depth]=sid; lidat[depth]=0
    }
    if (dir=="location") { lid++; lidat[depth]=lid }
}
{
    line=$0
    if (line ~ /^# configuration file /) {
        file=line
        sub(/^# configuration file /,"",file)
        sub(/:$/,"",file)
        next
    }
    lineno++
    s=line; out=""; q=""; esc=0
    for (i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if (esc) { out=out c; esc=0; continue }
        if (c=="\\") { out=out c; esc=1; continue }
        if (q!="") { if (c==q) q=""; out=out c; continue }
        if (c=="\"" || c=="'") { q=c; out=out c; continue }
        if (c=="#") break
        out=out c
    }
    s=out; q=""
    for (i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if (q!="") {
            buf=buf c
            if (c==q) q=""
            continue
        }
        if (c=="\"" || c=="'") {
            q=c
            if (buf=="") stmtline=lineno
            buf=buf c
            continue
        }
        if (c==";") { if (buf=="") stmtline=lineno; emit(0); continue }
        if (c=="{") {
            nxt=substr(s,i+1,1)
            if (nxt ~ /[0-9,]/) {
                if (buf=="") stmtline=lineno
                buf=buf c; quant++
                continue
            }
            if (buf=="") stmtline=lineno
            t=trim(buf)
            if (t=="") continue
            if (match(t, /^[^ \t]+/)) { d=substr(t,1,RLENGTH); a=trim(substr(t,RLENGTH+1)) }
            else { d=t; a="" }
            push_block(d,a)
            emit(1)
            continue
        }
        if (c=="}") {
            if (quant>0) { buf=buf c; quant--; continue }
            emit(0)
            if (depth>0) depth--
            continue
        }
        if (buf=="") {
            if (c ~ /[ \t]/) continue
            stmtline=lineno
        }
        buf=buf c
    }
}
END { emit(0) }
AWK_EOF
}

declare -a L_DEPTH=() L_SID=() L_LID=() L_CTX=() L_DIR=() L_ARGS=() L_FILE=() L_LINE=() L_OPENS=()
CFG_N=0
load_config() {
    local f_depth f_sid f_lid f_ctx f_dir f_args f_file f_line f_opens
    CFG_N=0
    L_DEPTH=(); L_SID=(); L_LID=(); L_CTX=(); L_DIR=()
    L_ARGS=(); L_FILE=(); L_LINE=(); L_OPENS=()
    while IFS=$'\x1f' read -r f_depth f_sid f_lid f_ctx f_dir f_args f_file f_line f_opens; do
        L_DEPTH+=("$f_depth")
        L_SID+=("$f_sid")
        L_LID+=("$f_lid")
        L_CTX+=("$f_ctx")
        L_DIR+=("$f_dir")
        L_ARGS+=("$f_args")
        L_FILE+=("$f_file")
        L_LINE+=("$f_line")
        L_OPENS+=("$f_opens")
        CFG_N=$((CFG_N + 1))
    done < <(awk -v initfile="$CONFIG_MAIN" -f "$AWK_FILE" "$DUMP_FILE")
}

# ---------------------------------------------------------------------------
# Config query helpers
# ---------------------------------------------------------------------------
has_word() { [[ " $1 " == *" $2 "* ]]; }

unquote() {
    local s=$1
    s=${s#\"}; s=${s%\"}
    s=${s#\'}; s=${s%\'}
    printf '%s' "$s"
}

resolve_path() {
    local p
    p=$(unquote "$1")
    [[ $p == /* ]] || p="${NGINX_PREFIX:-/etc/nginx}/$p"
    printf '%s' "$p"
}

port_from_listen() {
    local a=${1%%[[:space:]]*} p
    case $a in unix:*) return 1 ;; esac
    if [[ $a == *:* ]]; then p=${a##*:}; else p=$a; fi
    [[ $p =~ ^[0-9]+$ ]] || p=80
    printf '%s' "$p"
}

server_has_dir() {
    local sid=$1 dir=$2 i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == "$dir" ]] && return 0
    done
    return 1
}

http_has_dir() {
    local dir=$1 i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == "$dir" ]] && return 0
    done
    return 1
}

server_last() {
    local sid=$1 dir=$2 i
    for ((i=CFG_N-1;i>=0;i--)); do
        if [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == "$dir" ]]; then
            printf '%s' "${L_ARGS[i]}"
            return 0
        fi
    done
    return 1
}

http_last() {
    local dir=$1 i
    for ((i=CFG_N-1;i>=0;i--)); do
        if [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == "$dir" ]]; then
            printf '%s' "${L_ARGS[i]}"
            return 0
        fi
    done
    return 1
}

main_last() {
    local dir=$1 i
    for ((i=CFG_N-1;i>=0;i--)); do
        if [[ ${L_DEPTH[i]} -eq 0 && ${L_DIR[i]} == "$dir" ]]; then
            printf '%s' "${L_ARGS[i]}"
            return 0
        fi
    done
    return 1
}

effective_last() {
    local sid=$1 dir=$2
    server_last "$sid" "$dir" || http_last "$dir"
}

server_listens() {
    local sid=$1 i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == listen ]] && printf '%s\n' "${L_ARGS[i]}"
    done
}

server_ports() {
    local sid=$1 a p
    while IFS= read -r a; do
        p=$(port_from_listen "$a") || continue
        printf '%s\n' "$p"
    done < <(server_listens "$sid")
}

server_names() {
    local sid=$1 i n
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == server_name ]] || continue
        for n in ${L_ARGS[i]}; do
            n=${n%\"}; n=${n#\"}; n=${n%\'}; n=${n#\'}
            [[ -z $n || $n == "_" || $n == \$* || $n == "~"* || $n == "*"* ]] && continue
            printf '%s\n' "$n"
        done
    done
}

all_domains() {
    local i d
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -gt 0 && ${L_DIR[i]} == server_name ]] || continue
        [[ ${L_CTX[i]} == "http>"* ]] || continue
        server_names "${L_SID[i]}"
    done | awk '!seen[$0]++'
}

server_is_tls() {
    local sid=$1 a
    while IFS= read -r a; do
        has_word "$a" ssl && return 0
        has_word "$a" quic && return 0
    done < <(server_listens "$sid")
    return 1
}

server_has_http2() {
    local sid=$1 a v
    v=$(server_last "$sid" http2) || true
    [[ $v == on ]] && return 0
    v=$(http_last http2) || true
    [[ $v == on ]] && return 0
    while IFS= read -r a; do
        has_word "$a" http2 && return 0
    done < <(server_listens "$sid")
    return 1
}

server_label() {
    local sid=$1 names
    names=$(server_names "$sid" | paste -sd, - 2>/dev/null || true)
    printf 'server[%s]%s' "$sid" "${names:+ ($names)}"
}

has_header() {
    local sid=$1 i count=0 lname=${2,,}
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == add_header ]] || continue
        count=$((count + 1))
        [[ ${L_ARGS[i],,} == *"$lname"* ]] && return 0
    done
    (( count > 0 )) && return 1
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == add_header ]] || continue
        [[ ${L_ARGS[i],,} == *"$lname"* ]] && return 0
    done
    return 1
}

header_max_age() {
    local sid=$1 i m
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == add_header ]] || continue
        [[ ${L_ARGS[i],,} == *strict-transport-security* ]] || continue
        m=$(grep -oiE 'max-age=[0-9]+' <<< "${L_ARGS[i]}" | head -n1)
        [[ -n $m ]] && { printf '%s' "${m#*=}"; return 0; }
    done
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == add_header ]] || continue
        [[ ${L_ARGS[i],,} == *strict-transport-security* ]] || continue
        m=$(grep -oiE 'max-age=[0-9]+' <<< "${L_ARGS[i]}" | head -n1)
        [[ -n $m ]] && { printf '%s' "${m#*=}"; return 0; }
    done
    return 1
}

location_header_args() {
    local lid=$1 i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_LID[i]} -eq $lid && ${L_DIR[i]} == location ]] || continue
        printf '%s' "${L_ARGS[i]}"
        return 0
    done
    return 1
}

ctx_has_dir() {
    local lid=$1 dir=$2 i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_LID[i]} -eq $lid && ${L_DIR[i]} == "$dir" ]] && return 0
    done
    return 1
}

count_dir() {
    local dir=$1 i n=0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == "$dir" ]] && n=$((n + 1))
    done
    printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Runtime / permission helpers
# ---------------------------------------------------------------------------
NGINX_MASTER_PID=""
NGINX_MASTER_USER=""
NGINX_WORKER_USERS=""
NGINX_WORKER_COUNT=0
NGINX_RUNNING=0
WORKER_USER=""
declare -a ALL_SERVERS=() TLS_SERVERS=() HTTP2_SERVERS=()
HTTP2_ENABLED=0

declare -A ALPN_RESULT=() CERT_STATE=() CERT_MATCH=()
LIVE_TLS10=0
LIVE_TLS11=0
LIVE_SERVER_HEADER=""
LIVE_READY=0

detect_runtime() {
    local pid user args
    NGINX_MASTER_PID=""; NGINX_MASTER_USER=""; NGINX_WORKER_USERS=""
    NGINX_WORKER_COUNT=0; NGINX_RUNNING=0
    while read -r pid _ user args; do
        [[ -z ${pid:-} ]] && continue
        case $args in
            *"nginx: master process"*)
                NGINX_MASTER_PID=$pid
                NGINX_MASTER_USER=$user
                NGINX_RUNNING=1
                ;;
            *"nginx: worker process"*)
                NGINX_RUNNING=1
                NGINX_WORKER_COUNT=$((NGINX_WORKER_COUNT + 1))
                case " $NGINX_WORKER_USERS " in
                    *" $user "*) ;;
                    *) NGINX_WORKER_USERS+=" $user" ;;
                esac
                ;;
        esac
    done < <(ps -eo pid=,ppid=,user=,args= 2>/dev/null)
    if [[ -z $NGINX_MASTER_PID ]] && has_cmd pgrep; then
        pid=$(pgrep -x nginx 2>/dev/null | head -n1) || true
        [[ -n $pid ]] && { NGINX_MASTER_PID=$pid; NGINX_RUNNING=1; }
    fi
}

resolve_worker_user() {
    local u
    u=$(main_last user) || true
    u=$(unquote "$u")
    if [[ -n $u ]]; then
        WORKER_USER=$u
    elif [[ -n $NGINX_WORKER_USERS ]]; then
        WORKER_USER=${NGINX_WORKER_USERS# }
        WORKER_USER=${WORKER_USER%% *}
    else
        WORKER_USER="nobody"
    fi
}

detect_servers() {
    local i sid
    local -A seen=()
    ALL_SERVERS=()
    for ((i=0;i<CFG_N;i++)); do
        sid=${L_SID[i]}
        (( sid > 0 )) || continue
        [[ ${L_CTX[i]} == "http>"* ]] || continue
        [[ -n ${seen[$sid]:-} ]] && continue
        seen[$sid]=1
        ALL_SERVERS+=("$sid")
    done
}

detect_http2() {
    local i sid
    HTTP2_ENABLED=0
    HTTP2_SERVERS=()
    for ((i=0;i<CFG_N;i++)); do
        if [[ ${L_DIR[i]} == http2 && ${L_ARGS[i]} == on ]]; then HTTP2_ENABLED=1; fi
        if [[ ${L_DIR[i]} == listen ]] && has_word "${L_ARGS[i]}" http2; then HTTP2_ENABLED=1; fi
    done
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        server_has_http2 "$sid" && HTTP2_SERVERS+=("$sid")
    done
}

detect_tls_servers() {
    local sid
    TLS_SERVERS=()
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        server_is_tls "$sid" && TLS_SERVERS+=("$sid")
    done
}

stat_mode() { stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1" 2>/dev/null; }
stat_owner() { stat -c '%U' -- "$1" 2>/dev/null || stat -f '%Su' -- "$1" 2>/dev/null; }
stat_group() { stat -c '%G' -- "$1" 2>/dev/null || stat -f '%Sg' -- "$1" 2>/dev/null; }

perm_has() {
    local mode=$1 bit=$2
    [[ -z $mode ]] && return 1
    (( 8#$mode & 8#$bit ))
}

is_world_writable() { perm_has "$(stat_mode "$1")" 002; }
is_group_writable() { perm_has "$(stat_mode "$1")" 020; }
is_world_readable() { perm_has "$(stat_mode "$1")" 004; }
is_owner_writable() { perm_has "$(stat_mode "$1")" 200; }

# ---------------------------------------------------------------------------
# ENV checks
# ---------------------------------------------------------------------------
check_env() {
    if [[ -n $NGINX_BIN ]]; then
        emit ENV-001 pass "nginx binary: $NGINX_BIN" "" ""
    else
        emit ENV-001 skip "no nginx binary found (offline mode)" "" ""
    fi

    if [[ -n $NGINX_VERSION ]]; then
        emit ENV-002 pass "nginx/$NGINX_VERSION" "" ""
    else
        emit ENV-002 warn "could not determine the nginx version; CVE checks are disabled (use --nginx-version)" \
            "Pass --nginx-version <x.y.z> or run where nginx -v works." ""
    fi

    if [[ $NGINX_TEST_OK -eq 1 ]]; then
        emit ENV-003 pass "nginx -t accepted the configuration" "" ""
    elif [[ $NGINX_TEST_OK -eq 0 ]]; then
        emit ENV-003 fail "nginx rejected the configuration: ${NGINX_ERR:-unknown error}" \
            "Run nginx -t and fix the reported error before reloading." ""
    else
        emit ENV-003 skip "configuration test not run (offline dump)" "" ""
    fi

    if [[ $NGINX_RUNNING -eq 1 ]]; then
        emit ENV-004 pass "master PID ${NGINX_MASTER_PID:-?} user ${NGINX_MASTER_USER:-?}, ${NGINX_WORKER_COUNT} worker(s) as${NGINX_WORKER_USERS:- unknown}" "" ""
    else
        emit ENV-004 info "nginx does not appear to be running; runtime checks are limited" "" ""
    fi

    if [[ $EUID_IS_ROOT -eq 1 ]]; then
        emit ENV-005 pass "running as root; full permission and process checks available" "" ""
    else
        emit ENV-005 info "running unprivileged; some permission checks may be incomplete (sudo -n is tried when available)" \
            "Re-run with sudo for complete results." ""
    fi
}

# ---------------------------------------------------------------------------
# HTTP/2 checks
# ---------------------------------------------------------------------------
check_http2() {
    local i a sid v names d

    if [[ $HTTP2_ENABLED -eq 1 ]]; then
        emit H2-001 pass "HTTP/2 is enabled (${#HTTP2_SERVERS[@]} server block(s))" "" "https://nginx.org/en/docs/http/ngx_http_v2_module.html"
    else
        emit H2-001 info "HTTP/2 is not enabled on this configuration" \
            "Add 'http2 on;' to TLS server blocks (nginx 1.25.1+) or 'listen 443 ssl http2;' on older versions." ""
    fi

    # H2-002 deprecated listen ... http2
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == listen ]] || continue
        has_word "${L_ARGS[i]}" http2 || continue
        if [[ -z $NGINX_VERSION ]] || ver_ge "$NGINX_VERSION" "1.25.1"; then
            emit H2-002 warn "deprecated 'listen ... http2' at ${L_CTX[i]} (${L_FILE[i]}:${L_LINE[i]})" \
                "Use 'listen 443 ssl;' plus 'http2 on;' (nginx 1.25.1+)." "https://nginx.org/en/docs/http/ngx_http_v2_module.html"
        fi
    done

    # H2-003 h2c / HTTP/2 without TLS
    for sid in ${HTTP2_SERVERS[@]+"${HTTP2_SERVERS[@]}"}; do
        server_is_tls "$sid" && continue
        emit H2-003 warn "HTTP/2 is enabled for non-TLS $(server_label "$sid")" \
            "Enable HTTP/2 only on TLS listeners; cleartext h2c bypasses TLS protections and is rarely needed." ""
    done
    if [[ $HTTP2_ENABLED -eq 1 ]] && [[ ${#HTTP2_SERVERS[@]} -eq 0 ]]; then
        # http-level http2 on applies to every server
        for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
            server_is_tls "$sid" && continue
            emit H2-003 warn "http-level 'http2 on' enables h2c for non-TLS $(server_label "$sid")" \
                "Move 'http2 on;' into TLS server blocks." ""
        done
    fi

    # H2-004 concurrent streams
    v=$(http_last http2_max_concurrent_streams) || true
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        local sv
        sv=$(server_last "$sid" http2_max_concurrent_streams) || true
        [[ -n $sv ]] && v=$sv
    done
    if [[ -n $v && $v =~ ^[0-9]+$ ]] && (( v > 128 )); then
        emit H2-004 warn "http2_max_concurrent_streams is ${v} (default 128)" \
            "Lower it to 128 or less to reduce per-connection resource use." ""
    fi

    # H2-005 keepalive_requests
    v=$(http_last keepalive_requests) || true
    if [[ -n $v && $v =~ ^[0-9]+$ ]] && (( v > 1000 )); then
        emit H2-005 warn "keepalive_requests is ${v}; values above 1000 increase HTTP/2 abuse impact" \
            "Set 'keepalive_requests 1000;' (the nginx 1.25.3+ default)." ""
    fi

    # H2-006 Rapid Reset
    if [[ $HTTP2_ENABLED -eq 1 ]]; then
        v=$(http_last keepalive_requests) || true
        if [[ -z $NGINX_VERSION ]]; then
            emit H2-006 skip "nginx version unknown; cannot evaluate CVE-2023-44487 exposure" "" ""
        elif ! ver_ge "$NGINX_VERSION" "1.25.3"; then
            if [[ -n $v && $v =~ ^[0-9]+$ ]] && (( v <= 1000 )); then
                emit H2-006 info "nginx/$NGINX_VERSION predates 1.25.3, but keepalive_requests ${v} limits Rapid Reset impact" \
                    "Upgrade to nginx 1.25.3+ (or a current stable branch) when possible." "https://nginx.org/en/docs/http/ngx_http_v2_module.html"
            else
                emit H2-006 fail "nginx/$NGINX_VERSION is exposed to CVE-2023-44487 (HTTP/2 Rapid Reset) with HTTP/2 enabled" \
                    "Upgrade to nginx 1.25.3+ and keep keepalive_requests at 1000 or lower." "https://cve.org/CVERecord?id=CVE-2023-44487"
            fi
        elif [[ -n $v && $v =~ ^[0-9]+$ ]] && (( v > 1000 )); then
            emit H2-006 warn "keepalive_requests ${v} raises exposure to HTTP/2 stream-flood attacks" \
                "Set 'keepalive_requests 1000;'." "https://cve.org/CVERecord?id=CVE-2023-44487"
        else
            emit H2-006 pass "nginx/$NGINX_VERSION includes Rapid Reset mitigations" "" "https://cve.org/CVERecord?id=CVE-2023-44487"
        fi
    fi

    # H2-007 http2_push
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == http2_push ]] || continue
        emit H2-007 info "http2_push at ${L_CTX[i]} (${L_FILE[i]}:${L_LINE[i]})" \
            "Server push is deprecated and removed in nginx 1.25.1+; remove the directive." ""
    done

    # H2-010 invalid values
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == http2 ]] || continue
        [[ ${L_ARGS[i]} == on || ${L_ARGS[i]} == off ]] && continue
        emit H2-010 warn "unexpected 'http2 ${L_ARGS[i]};' at ${L_CTX[i]}" "Use 'http2 on;' or 'http2 off;'." ""
    done

    # H2-008 / H2-009 live ALPN
    if [[ $LIVE_READY -eq 1 ]]; then
        for sid in ${HTTP2_SERVERS[@]+"${HTTP2_SERVERS[@]}"}; do
            server_is_tls "$sid" || continue
            names=$(server_names "$sid" | head -n 5)
            [[ -z $names ]] && names="localhost"
            while IFS= read -r d; do
                [[ -z $d ]] && continue
                case ${ALPN_RESULT[$d]:-} in
                    h2) emit H2-008 pass "ALPN negotiated h2 for $d" "" "" ;;
                    none) emit H2-008 fail "HTTP/2 is configured but $d did not negotiate ALPN h2" \
                        "Check that the TLS listener serves this server block and that the client offers h2." "" ;;
                    error|"") emit H2-008 skip "could not probe ALPN for $d" "" "" ;;
                    *) emit H2-008 warn "$d negotiated ALPN '${ALPN_RESULT[$d]}' instead of h2" \
                        "Verify the listener and TLS configuration for this name." "" ;;
                esac
            done <<< "$names"
        done
        for sid in ${TLS_SERVERS[@]+"${TLS_SERVERS[@]}"}; do
            server_has_http2 "$sid" && continue
            names=$(server_names "$sid" | head -n 5)
            [[ -z $names ]] && names="localhost"
            while IFS= read -r d; do
                [[ -z $d ]] && continue
                [[ ${ALPN_RESULT[$d]:-} == h2 ]] && emit H2-009 info "$d negotiated h2 although HTTP/2 is not enabled for this block" \
                    "Confirm whether HTTP/2 is intended for this virtual host." ""
            done <<< "$names"
        done
    elif [[ $HTTP2_ENABLED -eq 1 ]]; then
        emit H2-008 skip "live ALPN probe disabled (use --live to enable)" "" ""
    fi
}

# ---------------------------------------------------------------------------
# TLS checks
# ---------------------------------------------------------------------------
first_token() { printf '%s' "${1%%[[:space:]]*}"; }

cert_args_for_server() {
    local sid=$1 i found=0 p
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == ssl_certificate ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        printf '%s\n' "$p"; found=1
    done
    (( found )) && return 0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == ssl_certificate ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        printf '%s\n' "$p"
    done
}

key_args_for_server() {
    local sid=$1 i found=0 p
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == ssl_certificate_key ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        printf '%s\n' "$p"; found=1
    done
    (( found )) && return 0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == ssl_certificate_key ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        printf '%s\n' "$p"
    done
}

cert_state() {
    local p=$1 subj iss
    has_cmd openssl || { printf 'unknown'; return; }
    openssl x509 -in "$p" -noout -checkend 0 >/dev/null 2>&1 || { printf 'expired'; return; }
    openssl x509 -in "$p" -noout -checkend 2592000 >/dev/null 2>&1 || { printf 'expiring'; return; }
    subj=$(openssl x509 -in "$p" -noout -subject 2>/dev/null)
    iss=$(openssl x509 -in "$p" -noout -issuer 2>/dev/null)
    subj=${subj#subject=}; iss=${iss#issuer=}
    if [[ -n $subj && $subj == "$iss" ]]; then printf 'selfsigned'; else printf 'ok'; fi
}

weak_ciphers() {
    local ciphers=$1 tok weak=""
    local IFS=:
    for tok in $ciphers; do
        [[ $tok == "!"* || $tok == "+"* ]] && continue
        tok=${tok#-}
        tok=${tok//\"/}; tok=${tok//\'/}
        case ${tok,,} in
            *null*|*export*|*rc4*|*3des*|*des*|*md5*|*anon*|*adh*) weak+=" $tok" ;;
        esac
    done
    printf '%s' "$weak"
}

header_has_always() {
    local sid=$1 i count=0 lname=${2,,}
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq $sid && ${L_LID[i]} -eq 0 && ${L_DIR[i]} == add_header ]] || continue
        [[ ${L_ARGS[i],,} == *"$lname"* ]] || continue
        count=$((count + 1))
        has_word "${L_ARGS[i]}" always && return 0
    done
    (( count > 0 )) && return 1
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_SID[i]} -eq 0 && ${L_LID[i]} -eq 0 && ${L_DEPTH[i]} -eq 1 && ${L_DIR[i]} == add_header ]] || continue
        [[ ${L_ARGS[i],,} == *"$lname"* ]] || continue
        has_word "${L_ARGS[i]}" always && return 0
    done
    return 1
}

check_tls() {
    local sid protos ciphers v age cp kp m st cert_found names d

    if [[ ${#TLS_SERVERS[@]} -eq 0 ]]; then
        emit TLS-001 skip "no TLS server blocks found" "" ""
        return 0
    fi

    for sid in ${TLS_SERVERS[@]+"${TLS_SERVERS[@]}"}; do
        # TLS-001 protocols
        protos=$(effective_last "$sid" ssl_protocols) || true
        protos=${protos//\"/}; protos=${protos//\'/}
        if [[ -z $protos ]]; then
            if [[ -z $NGINX_VERSION ]] || ! ver_ge "$NGINX_VERSION" "1.23.4"; then
                protos="TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
            fi
        fi
        if has_word "$protos" TLSv1 || has_word "$protos" TLSv1.1 || has_word "$protos" SSLv3; then
            emit TLS-001 fail "$(server_label "$sid") enables legacy TLS: $protos" \
                "Use 'ssl_protocols TLSv1.2 TLSv1.3;' and keep OpenSSL current." "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"
        fi

        # TLS-002 ciphers
        ciphers=$(effective_last "$sid" ssl_ciphers) || true
        ciphers=${ciphers//\"/}; ciphers=${ciphers//\'/}
        if [[ -n $ciphers ]]; then
            local weak
            weak=$(weak_ciphers "$ciphers")
            if [[ -n $weak ]]; then
                emit TLS-002 fail "$(server_label "$sid") enables weak ciphers:${weak}" \
                    "Remove NULL/EXPORT/RC4/DES/MD5/anon ciphers and use a modern Mozilla-style list." ""
            fi
        fi

        # TLS-003 server cipher preference
        v=$(effective_last "$sid" ssl_prefer_server_ciphers) || true
        [[ $v == off ]] && emit TLS-003 warn "$(server_label "$sid") sets ssl_prefer_server_ciphers off" \
            "Set 'ssl_prefer_server_ciphers on;' unless you have a specific reason." ""

        # HSTS
        if has_header "$sid" "Strict-Transport-Security"; then
            age=$(header_max_age "$sid") || true
            if [[ -n $age && $age =~ ^[0-9]+$ ]] && (( age < 15552000 )); then
                emit TLS-005 warn "$(server_label "$sid") HSTS max-age is ${age}s (recommended >= 15552000)" \
                    "Use 'max-age=31536000; includeSubDomains' once HTTPS is stable." ""
            fi
            header_has_always "$sid" "Strict-Transport-Security" || \
                emit TLS-016 info "$(server_label "$sid") HSTS header does not use 'always'" \
                    "Add 'always' so the header is sent on error responses too." ""
        else
            emit TLS-004 warn "$(server_label "$sid") does not send Strict-Transport-Security" \
                "Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;'." ""
        fi

        # Certificates
        cert_found=0
        while IFS= read -r cp; do
            [[ -z $cp || ! -r $cp ]] && continue
            cert_found=1
            st=$(cert_state "$cp")
            case $st in
                expired)  emit TLS-006 fail "$(server_label "$sid") certificate expired: $cp" \
                              "Renew the certificate and reload nginx." "" ;;
                expiring) emit TLS-006 warn "$(server_label "$sid") certificate expires within 30 days: $cp" \
                              "Renew the certificate and reload nginx." "" ;;
                selfsigned) emit TLS-008 info "$(server_label "$sid") uses a self-signed certificate: $cp" \
                              "Use a publicly trusted certificate for public services." "" ;;
            esac
        done < <(cert_args_for_server "$sid")

        # Private keys
        while IFS= read -r kp; do
            [[ -z $kp || ! -r $kp ]] && continue
            m=$(stat_mode "$kp")
            if perm_has "$m" 004; then
                emit TLS-007 fail "private key is world-readable: $kp (mode $m)" \
                    "chmod 600 the key and ensure it is owned by root." ""
            elif perm_has "$m" 040; then
                emit TLS-007 warn "private key is group-readable: $kp (mode $m)" \
                    "chmod 600 the key unless a specific service group needs access." ""
            fi
        done < <(key_args_for_server "$sid")

        # TLS-015 certificate missing
        if [[ $cert_found -eq 0 ]] && [[ -z $(cert_args_for_server "$sid") ]]; then
            emit TLS-015 fail "$(server_label "$sid") has a TLS listener but no ssl_certificate" \
                "Add ssl_certificate and ssl_certificate_key, or remove ssl from the listener." ""
        fi

        # OCSP
        v=$(effective_last "$sid" ssl_stapling) || true
        if [[ $v != on ]]; then
            emit TLS-009 info "$(server_label "$sid") does not enable OCSP stapling" \
                "Enable 'ssl_stapling on; ssl_stapling_verify on;' with a resolver." ""
        else
            local resolver
            resolver=$(http_last resolver) || true
            [[ -z $resolver ]] && emit TLS-010 warn "$(server_label "$sid") enables OCSP stapling without a resolver" \
                "Add 'resolver 1.1.1.1 8.8.8.8 valid=300s;' so stapling can work." ""
        fi

        # Client cert mode
        v=$(effective_last "$sid" ssl_verify_client) || true
        [[ $v == optional_no_ca ]] && emit TLS-011 warn "$(server_label "$sid") uses ssl_verify_client optional_no_ca" \
            "Prefer 'on' with a trusted CA; optional_no_ca accepts unverified client certificates." ""

        # Session cache
        v=$(effective_last "$sid" ssl_session_cache) || true
        [[ $v == off ]] && emit TLS-013 info "$(server_label "$sid") disables the TLS session cache" \
            "Use 'ssl_session_cache shared:SSL:10m;' for performance." ""

        # Live certificate state when files are not readable
        if [[ $cert_found -eq 0 && $LIVE_READY -eq 1 ]]; then
            names=$(server_names "$sid" | head -n 3)
            [[ -z $names ]] && names="localhost"
            while IFS= read -r d; do
                [[ -z $d ]] && continue
                case ${CERT_STATE[$d]:-} in
                    expired)  emit TLS-017 fail "live certificate for $d is expired" "Renew the certificate." "" ;;
                    expiring) emit TLS-017 warn "live certificate for $d expires within 30 days" "Renew the certificate." "" ;;
                esac
                [[ ${CERT_MATCH[$d]:-1} == 0 ]] && emit TLS-014 warn "live certificate does not match $d" \
                    "Check server_name, SNI and certificate SANs." ""
            done <<< "$names"
        fi
    done

    # Live legacy protocol acceptance (once)
    if [[ $LIVE_READY -eq 1 ]]; then
        if [[ $LIVE_TLS10 -eq 1 || $LIVE_TLS11 -eq 1 ]]; then
            local vers=""
            [[ $LIVE_TLS10 -eq 1 ]] && vers+=" TLSv1.0"
            [[ $LIVE_TLS11 -eq 1 ]] && vers+=" TLSv1.1"
            emit TLS-012 fail "the live listener accepts legacy TLS:$vers" \
                "Disable TLSv1.0/1.1 in ssl_protocols and at the load balancer." ""
        fi
    fi
}

# ---------------------------------------------------------------------------
# nginx -> root checks
# ---------------------------------------------------------------------------
check_privileges() {
    local u line uid shell v i f m o dir p
    local -A files=() dirs=() seen_roots=()

    # ROOT-002 user directive
    u=$(main_last user) || true
    u=$(unquote "$u")
    if [[ -n $u ]]; then
        uid=""
        shell=""
        if has_cmd getent; then
            line=$(getent passwd "$u" 2>/dev/null) || true
            [[ -n $line ]] && { uid=$(cut -d: -f3 <<< "$line"); shell=$(cut -d: -f7 <<< "$line"); }
        elif has_cmd id; then
            uid=$(id -u "$u" 2>/dev/null) || true
        fi
        if [[ $u == root || $u == 0 || ${uid:-x} == 0 ]]; then
            emit ROOT-002 fail "nginx is configured to run workers as root (user $u)" \
                "Set 'user www-data;' (or another unprivileged account) in nginx.conf." ""
        elif [[ -n $shell && $shell != */nologin && $shell != */false && $shell != /bin/false ]]; then
            emit ROOT-014 warn "worker user '$u' has a login shell ($shell)" \
                "Use an account with /usr/sbin/nologin." ""
        fi
    fi

    # ROOT-001 workers running as root
    if [[ $MODE == "offline (dump)" ]]; then
        emit ROOT-001 skip "offline dump; worker identity not available" \
            "Run nginx2root on the target host for process checks." ""
    elif [[ $NGINX_RUNNING -eq 1 && -n $NGINX_WORKER_USERS ]]; then
        case " $NGINX_WORKER_USERS " in
            *" root "*)
                emit ROOT-001 fail "nginx worker processes are running as root (${NGINX_WORKER_COUNT} worker(s))" \
                    "A compromised worker would own the host. Set 'user www-data;' and reload nginx." ""
                ;;
            *)
                emit ROOT-001 pass "worker processes run as:${NGINX_WORKER_USERS}" "" ""
                ;;
        esac
    elif [[ $NGINX_RUNNING -eq 1 ]]; then
        emit ROOT-001 info "nginx is running but no worker processes were found" "" ""
    else
        emit ROOT-001 skip "nginx is not running; worker identity not available" "" ""
    fi

    # ROOT-003 master_process off
    v=$(main_last master_process) || true
    if [[ $v == off ]]; then
        if [[ $MODE != "offline (dump)" && ( $EUID_IS_ROOT -eq 1 || $NGINX_MASTER_USER == root ) ]]; then
            emit ROOT-003 fail "master_process is off and nginx runs as root; requests are handled by the root process" \
                "Enable the master process and run workers as an unprivileged user." ""
        else
            emit ROOT-003 warn "master_process is off; there is no privileged/unprivileged process split" \
                "Use the default master/worker model." ""
        fi
    fi

    if [[ $MODE == "offline (dump)" ]]; then
        emit ROOT-004 skip "file permission checks skipped for an offline dump" \
            "Run nginx2root on the target host for permission checks." ""
    else
        # ROOT-004 config file permissions
        for ((i=0;i<CFG_N;i++)); do
            f=${L_FILE[i]}
            [[ -n $f && -f $f ]] && files[$f]=1
        done
        [[ -n $CONFIG_MAIN && -f $CONFIG_MAIN ]] && files[$CONFIG_MAIN]=1

        local world="" group="" nonroot=""
        for f in "${!files[@]}"; do
            m=$(stat_mode "$f"); o=$(stat_owner "$f")
            if perm_has "$m" 002; then world+=" $f"
            elif perm_has "$m" 020; then group+=" $f"
            elif [[ $o != root ]] && perm_has "$m" 200; then nonroot+=" $f"
            fi
            dirs[$(dirname -- "$f")]=1
        done
        if [[ -n $world ]]; then
            emit ROOT-004 fail "world-writable nginx configuration:${world}" \
                "chmod o-w and ensure only root can write nginx configuration." ""
        elif [[ -n $group || -n $nonroot ]]; then
            emit ROOT-004 fail "nginx configuration is writable by a non-root account:${group}${nonroot}" \
                "chown root:root and chmod 644 the configuration; restrict write access to root." ""
        elif [[ ${#files[@]} -gt 0 ]]; then
            emit ROOT-004 pass "nginx configuration files are not writable by non-root users" "" ""
        fi

        # ROOT-005 config directories
        local dworld="" dgroup=""
        for dir in "${!dirs[@]}"; do
            [[ -d $dir ]] || continue
            m=$(stat_mode "$dir")
            if perm_has "$m" 002; then dworld+=" $dir"
            elif perm_has "$m" 020; then dgroup+=" $dir"
            fi
        done
        if [[ -n $dworld ]]; then
            emit ROOT-005 fail "world-writable nginx configuration directory:${dworld}" \
                "chmod o-w the directory; a local user could add an include." ""
        elif [[ -n $dgroup ]]; then
            emit ROOT-005 fail "group-writable nginx configuration directory:${dgroup}" \
                "chmod g-w the directory and restrict the group." ""
        elif [[ ${#dirs[@]} -gt 0 ]]; then
            emit ROOT-005 pass "nginx configuration directories are not writable by non-root users" "" ""
        fi

        # ROOT-007 nginx binary
        if [[ -n $NGINX_BIN && -f $NGINX_BIN ]]; then
            m=$(stat_mode "$NGINX_BIN"); o=$(stat_owner "$NGINX_BIN")
            if perm_has "$m" 002; then
                emit ROOT-007 fail "nginx binary is world-writable: $NGINX_BIN (mode $m)" \
                    "chmod 755 and chown root:root the binary." ""
            elif perm_has "$m" 020; then
                emit ROOT-007 fail "nginx binary is group-writable: $NGINX_BIN (mode $m)" \
                    "chmod 755 and restrict the owning group." ""
            elif [[ $o != root ]] && perm_has "$m" 200; then
                emit ROOT-007 fail "nginx binary is owned by non-root user $o: $NGINX_BIN" \
                    "chown root:root the binary; root executes it." ""
            else
                emit ROOT-007 pass "nginx binary is root-owned and not writable by others" "" ""
            fi
        fi

        # ROOT-009 pid file directory
        p=$(main_last pid) || true
        [[ -z $p ]] && p="/run/nginx.pid"
        p=$(resolve_path "$p")
        dir=$(dirname -- "$p")
        if [[ -d $dir ]] && is_world_writable "$dir"; then
            emit ROOT-009 fail "pid file directory is world-writable: $dir" \
                "Move the pid file to /run or another root-owned directory." ""
        fi
    fi

    # ROOT-006 include from risky path
    local risky=""
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == include ]] || continue
        p=$(unquote "$(first_token "${L_ARGS[i]}")")
        p=${p%%[*?]*}
        p=$(resolve_path "$p")
        dir=$(dirname -- "$p")
        case $dir in
            /tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*|/home|/home/*)
                risky+=" ${L_ARGS[i]} (${L_FILE[i]}:${L_LINE[i]})" ;;
            *)
                [[ -d $dir ]] && is_world_writable "$dir" && risky+=" ${L_ARGS[i]} (world-writable $dir)" ;;
        esac
    done
    if [[ -n $risky ]]; then
        emit ROOT-006 fail "nginx includes files from a risky location:${risky}" \
            "Keep includes under /etc/nginx or another root-owned directory." ""
    fi

    # ROOT-008 writable web roots
    local wroots=""
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == root || ${L_DIR[i]} == alias ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        [[ $p == *'$'* || $p == *'~'* ]] && continue
        [[ -d $p ]] || continue
        m=$(stat_mode "$p"); o=$(stat_owner "$p")
        case $p in
            /|/etc|/etc/*|/root|/root/*|/home|/home/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/var/lib|/var/lib/*) continue ;;
        esac
        [[ -n ${seen_roots[$p]:-} ]] && continue
        seen_roots[$p]=1
        if perm_has "$m" 002; then
            wroots+=" $p (world-writable)"
        elif [[ $WORKER_USER != root && $o == "$WORKER_USER" ]] && perm_has "$m" 200; then
            wroots+=" $p (writable by $WORKER_USER)"
        fi
    done
    if [[ -n $wroots ]]; then
        emit ROOT-008 fail "web content directories are writable by the web user:${wroots}" \
            "Web content should be root-owned and read-only to nginx; use a deploy user with deliberate access." ""
    fi

    # ROOT-010 capabilities
    if [[ $MODE != "offline (dump)" && -n $NGINX_MASTER_PID && -r /proc/$NGINX_MASTER_PID/status && $NGINX_MASTER_USER != root ]]; then
        local cap decoded
        cap=$(awk '/^CapEff:/{print $2}' "/proc/$NGINX_MASTER_PID/status" 2>/dev/null)
        decoded=""
        if [[ -n $cap && $cap != "0000000000000000" ]] && has_cmd capsh; then
            decoded=$(capsh --decode="$cap" 2>/dev/null) || true
        fi
        case ${decoded,,} in
            *cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_dac_read_search*)
                emit ROOT-010 fail "nginx master has excessive capabilities: $decoded" \
                    "Restrict the unit to CAP_NET_BIND_SERVICE, CAP_SETUID, CAP_SETGID and CAP_CHROOT." "" ;;
        esac
    fi

    # systemd unit
    local unit="" miss=0
    for p in /etc/systemd/system/nginx.service /usr/lib/systemd/system/nginx.service \
             /lib/systemd/system/nginx.service /usr/local/lib/systemd/system/nginx.service; do
        [[ -f $p ]] && { unit=$p; break; }
    done
    if [[ -n $unit ]]; then
        grep -qi '^NoNewPrivileges=true' "$unit" || miss=$((miss + 1))
        grep -qi '^ProtectSystem=' "$unit" || miss=$((miss + 1))
        grep -qi '^ProtectHome=' "$unit" || miss=$((miss + 1))
        grep -qi '^PrivateTmp=true' "$unit" || miss=$((miss + 1))
        grep -qi '^CapabilityBoundingSet=' "$unit" || miss=$((miss + 1))
        if (( miss >= 3 )); then
            emit ROOT-011 info "systemd unit lacks hardening directives ($unit)" \
                "Consider NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp and CapabilityBoundingSet." ""
        fi
        while IFS= read -r line; do
            for p in $(grep -oE '/[^[:space:];]+' <<< "$line" 2>/dev/null); do
                [[ -f $p ]] || continue
                m=$(stat_mode "$p"); o=$(stat_owner "$p")
                if perm_has "$m" 002 || perm_has "$m" 020 || { [[ $o != root ]] && perm_has "$m" 200; }; then
                    emit ROOT-012 fail "systemd Exec* runs a writable script: $p (mode $m owner $o)" \
                        "Make the script root-owned and not writable by others." ""
                fi
            done
        done < <(grep -E '^Exec(StartPre|Start|Reload)=' "$unit" 2>/dev/null)
    else
        emit ROOT-011 skip "no systemd unit found" "" ""
    fi

    # ROOT-013 MAC
    local mac=""
    if has_cmd getenforce; then
        mac=$(getenforce 2>/dev/null) || true
        if [[ $mac == Enforcing ]]; then
            emit ROOT-013 pass "SELinux is enforcing" "" ""
        else
            emit ROOT-013 info "SELinux is ${mac:-not enforcing}" \
                "Consider enforcing SELinux or AppArmor for nginx." ""
        fi
    elif has_cmd aa-status; then
        if aa-status --enabled >/dev/null 2>&1; then
            emit ROOT-013 pass "AppArmor is enabled" "" ""
        else
            emit ROOT-013 info "AppArmor is not enabled" "Consider an AppArmor profile for nginx." ""
        fi
    else
        emit ROOT-013 info "no SELinux/AppArmor tooling detected" "" ""
    fi

    # ROOT-015 password files
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == auth_basic_user_file ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        if [[ -f $p ]] && is_world_readable "$p"; then
            emit ROOT-015 warn "basic-auth password file is world-readable: $p" \
                "chmod 640 and restrict it to the nginx group." ""
        fi
    done

    # ROOT-016 env
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == env ]] || continue
        emit ROOT-016 info "env directive exposes '${L_ARGS[i]}' to worker processes" \
            "Avoid putting secrets in nginx environment variables." ""
    done
}

# ---------------------------------------------------------------------------
# Configuration flaw checks
# ---------------------------------------------------------------------------
parse_time_seconds() {
    local v=$1 n
    case $v in
        *ms) n=${v%ms}; n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} / 1000 ))" ;;
        *s)  n=${v%s};  n=${n//[!0-9]/}; printf '%s' "${n:-0}" ;;
        *m)  n=${v%m};  n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} * 60 ))" ;;
        *h)  n=${v%h};  n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} * 3600 ))" ;;
        *d)  n=${v%d};  n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} * 86400 ))" ;;
        *)   n=${v//[!0-9]/}; printf '%s' "${n:-0}" ;;
    esac
}

parse_size_bytes() {
    local v=$1 n
    case $v in
        *k|*K) n=${v%[kK]}; n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} * 1024 ))" ;;
        *m|*M) n=${v%[mM]}; n=${n//[!0-9]/}; printf '%s' "$(( ${n:-0} * 1024 * 1024 ))" ;;
        *)     n=${v//[!0-9]/}; printf '%s' "${n:-0}" ;;
    esac
}

check_config() {
    local i sid v lid loc pattern ap p d m bad

    # CFG-001 server_tokens
    bad=""
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        v=$(effective_last "$sid" server_tokens) || true
        [[ $v != off ]] && bad+=" $(server_label "$sid")"
    done
    if [[ ${#ALL_SERVERS[@]} -eq 0 ]]; then
        v=$(http_last server_tokens) || true
        [[ $v != off ]] && bad=" global"
    fi
    if [[ -n $bad ]]; then
        emit CFG-001 warn "server_tokens is not disabled for:${bad}" \
            "Set 'server_tokens off;' to hide the nginx version in error pages and the Server header." ""
    else
        emit CFG-001 pass "server_tokens is off" "" ""
    fi

    # CFG-002 autoindex
    bad=""
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == autoindex && ${L_ARGS[i]} == on ]] || continue
        bad+=" ${L_CTX[i]} (${L_FILE[i]}:${L_LINE[i]})"
    done
    if [[ -n $bad ]]; then
        emit CFG-002 warn "directory listing is enabled:${bad}" \
            "Remove 'autoindex on;' or add authentication." ""
    else
        emit CFG-002 pass "directory listing is not enabled" "" ""
    fi

    # CFG-003 stub_status
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == stub_status ]] || continue
        lid=${L_LID[i]}
        if [[ $lid -eq 0 ]]; then
            emit CFG-003 fail "stub_status is enabled at ${L_CTX[i]} without a location restriction" \
                "Put stub_status in a location restricted with 'allow 127.0.0.1; deny all;'." ""
        elif ctx_has_dir "$lid" allow || ctx_has_dir "$lid" deny || ctx_has_dir "$lid" auth_basic; then
            if ctx_has_dir "$lid" allow && ! ctx_has_dir "$lid" deny; then
                emit CFG-003 warn "stub_status location has allow rules but no explicit deny all (${L_FILE[i]}:${L_LINE[i]})" \
                    "Add 'deny all;' after the allow list." ""
            else
                emit CFG-003 pass "stub_status is access-restricted" "" ""
            fi
        else
            emit CFG-003 fail "stub_status is publicly reachable at ${L_CTX[i]} (${L_FILE[i]}:${L_LINE[i]})" \
                "Restrict the status location to localhost or an authenticated admin network." ""
        fi
    done

    # CFG-004 alias traversal
    local alias_seen=0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == alias ]] || continue
        alias_seen=1
        lid=${L_LID[i]}
        loc=$(location_header_args "$lid") || continue
        pattern=$(first_token "$loc")
        ap=$(unquote "$(first_token "${L_ARGS[i]}")")
        case $pattern in
            "~"*|"="*|"^~"*|"@"*)
                emit CFG-004 warn "alias used inside a non-prefix location ($pattern) at ${L_FILE[i]}:${L_LINE[i]}" \
                    "Prefer root or a trailing-slash prefix location; audit capture groups carefully." ""
                ;;
            *)
                if [[ $pattern != */ && $ap == */ ]]; then
                    emit CFG-004 fail "alias traversal risk: location $pattern maps to $ap (${L_FILE[i]}:${L_LINE[i]})" \
                        "Add a trailing slash to the location (location $pattern/) or use root instead of alias." "https://nginx.org/en/docs/http/ngx_http_core_module.html#alias"
                elif [[ $pattern == */ && $ap != */ ]]; then
                    emit CFG-004 warn "alias path does not end with '/' but the location does ($pattern -> $ap)" \
                        "Keep trailing slashes consistent between location and alias." ""
                fi
                ;;
        esac
    done
    [[ $alias_seen -eq 0 ]] && emit CFG-004 pass "no alias directives to audit" "" ""

    # CFG-005 merge_slashes
    v=$(http_last merge_slashes) || true
    if [[ $v == off ]]; then
        emit CFG-005 warn "merge_slashes is off; duplicate slashes can bypass path-based rules" \
            "Keep merge_slashes on unless a legacy backend requires otherwise." ""
    else
        emit CFG-005 pass "merge_slashes is on (default)" "" ""
    fi

    # CFG-006 dotfiles
    local has_root=0 dot_deny=0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == root ]] && has_root=1
        if [[ ${L_DIR[i]} == location ]]; then
            case ${L_ARGS[i]} in
                *'\.'*|*'/.git'*|*'/.env'*|*'/.well-known'*) dot_deny=1 ;;
            esac
        fi
    done
    if [[ $has_root -eq 1 && $dot_deny -eq 0 ]]; then
        emit CFG-006 warn "no rule blocks access to dotfiles such as .git, .env or .htpasswd" \
            "Add 'location ~ /\\.(?!well-known) { deny all; }' or an equivalent rule." ""
    elif [[ $has_root -eq 1 ]]; then
        emit CFG-006 pass "dotfile access is blocked by a location rule" "" ""
    fi

    # CFG-007 WebDAV
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == dav_methods ]] || continue
        case ${L_ARGS[i],,} in
            *put*|*delete*|*mkcol*|*copy*|*move*)
                lid=${L_LID[i]}
                if ! ctx_has_dir "$lid" auth_basic && ! ctx_has_dir "$lid" allow && ! ctx_has_dir "$lid" deny && ! ctx_has_dir "$lid" satisfy; then
                    emit CFG-007 fail "WebDAV write methods are enabled without authentication at ${L_CTX[i]}" \
                        "Require auth or restrict by IP; disable dav_methods if unused." ""
                fi
                ;;
        esac
    done

    # CFG-008 / CFG-025 proxy_pass variables
    local dynamic=0 resolver_missing=0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == proxy_pass ]] || continue
        [[ ${L_ARGS[i]} == *'$'* ]] || continue
        dynamic=1
        if [[ ${L_ARGS[i]} == *'$http_'* ]]; then
            emit CFG-008 fail "proxy_pass uses a client-controlled header variable: ${L_ARGS[i]}" \
                "Never build upstream URLs from \$http_* variables; use a fixed upstream or a map." ""
        else
            emit CFG-008 warn "proxy_pass uses a variable: ${L_ARGS[i]} (${L_FILE[i]}:${L_LINE[i]})" \
                "Validate the variable with a map and pin the upstream to prevent SSRF." ""
        fi
    done
    if [[ $dynamic -eq 1 ]]; then
        v=$(http_last resolver) || true
        [[ -z $v ]] && resolver_missing=1
        if [[ $resolver_missing -eq 1 ]]; then
            emit CFG-025 warn "dynamic proxy_pass is used without a resolver" \
                "Add 'resolver' with valid= and use a variable only where required." ""
        fi
    fi

    # CFG-009 / CFG-010 security headers
    for sid in ${TLS_SERVERS[@]+"${TLS_SERVERS[@]}"}; do
        if ! has_header "$sid" "X-Content-Type-Options"; then
            emit CFG-009 warn "$(server_label "$sid") does not send X-Content-Type-Options" \
                "Add 'add_header X-Content-Type-Options nosniff always;'." ""
        fi
        if ! has_header "$sid" "X-Frame-Options" && ! has_header "$sid" "Content-Security-Policy"; then
            emit CFG-010 info "$(server_label "$sid") has no X-Frame-Options or CSP" \
                "Add a frame-ancestors CSP or X-Frame-Options DENY/SAMEORIGIN." ""
        fi
    done

    # CFG-011 sensitive root/alias
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == root || ${L_DIR[i]} == alias ]] || continue
        p=$(resolve_path "$(first_token "${L_ARGS[i]}")")
        case $p in
            /|/etc|/etc/*|/root|/root/*|/home|/home/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/var/lib|/var/lib/*)
                emit CFG-011 fail "sensitive path exposed via ${L_DIR[i]}: $p (${L_FILE[i]}:${L_LINE[i]})" \
                    "Point root/alias at a dedicated content directory, never at system paths." ""
                ;;
        esac
    done

    # CFG-012 port 443 without TLS
    local ports
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        ports=$(server_ports "$sid" | sort -u)
        grep -qx '443' <<< "$ports" || continue
        server_is_tls "$sid" && continue
        emit CFG-012 fail "$(server_label "$sid") listens on 443 without TLS" \
            "Add 'ssl' to the 443 listener and configure ssl_certificate." ""
    done

    # CFG-013 default_server
    local have80=0 have443=0
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == listen ]] || continue
        has_word "${L_ARGS[i]}" default_server || continue
        p=$(port_from_listen "${L_ARGS[i]}") || continue
        [[ $p == 80 ]] && have80=1
        [[ $p == 443 ]] && have443=1
    done
    if [[ $have80 -eq 0 || $have443 -eq 0 ]]; then
        emit CFG-013 info "no explicit default_server on port 80 and/or 443" \
            "Add a catch-all server block that rejects unknown Host headers." ""
    else
        emit CFG-013 pass "default_server is defined for 80 and 443" "" ""
    fi

    # CFG-014 proxy_pass inside if
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == proxy_pass ]] || continue
        [[ ${L_CTX[i]} == *">if "* ]] || continue
        emit CFG-014 warn "proxy_pass inside an if block at ${L_CTX[i]}" \
            "Use map or named locations; if+proxy_pass has known surprising behaviour." ""
    done

    # CFG-015 access_log off
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == access_log && ${L_ARGS[i]} == off ]] || continue
        emit CFG-015 info "access logging is disabled at ${L_CTX[i]}" \
            "Keep access logs for incident response unless privacy requirements forbid it." ""
    done

    # CFG-016 request body
    v=$(http_last client_max_body_size) || true
    if [[ $v == 0 ]]; then
        emit CFG-016 warn "http-level client_max_body_size is 0 (unlimited)" \
            "Set a realistic limit such as 10m to reduce disk/DoS exposure." ""
    fi
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        v=$(server_last "$sid" client_max_body_size) || true
        if [[ $v == 0 ]]; then
            emit CFG-016 warn "$(server_label "$sid") sets client_max_body_size 0 (unlimited)" \
                "Set a realistic limit such as 10m to reduce disk/DoS exposure." ""
        fi
    done

    # CFG-017 / CFG-018 header parsing
    v=$(http_last underscores_in_headers) || true
    [[ $v == on ]] && emit CFG-017 warn "underscores_in_headers is on" \
        "Leave it off; underscore headers are often used to bypass proxy filters." ""
    v=$(http_last ignore_invalid_headers) || true
    [[ $v == off ]] && emit CFG-018 warn "ignore_invalid_headers is off" \
        "Keep invalid-header rejection enabled." ""

    # CFG-019 plaintext redirects
    for ((i=0;i<CFG_N;i++)); do
        case ${L_DIR[i]} in return|rewrite) ;; *) continue ;; esac
        [[ ${L_ARGS[i]} == *'http://'* ]] || continue
        emit CFG-019 warn "redirect to plaintext HTTP at ${L_CTX[i]} (${L_FILE[i]}:${L_LINE[i]})" \
            "Redirect to https:// or use a relative URI." ""
    done

    # CFG-020 rate limiting
    if [[ $(count_dir limit_req) -eq 0 && $(count_dir limit_conn) -eq 0 ]]; then
        emit CFG-020 info "no limit_req or limit_conn rules found" \
            "Consider rate limiting login and API locations on internet-facing hosts." ""
    else
        emit CFG-020 pass "rate limiting is configured" "" ""
    fi

    # CFG-021 catch-all server_name
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        v=$(server_last "$sid" server_name) || true
        [[ $v == "_" ]] || continue
        local ds=0 a
        while IFS= read -r a; do has_word "$a" default_server && ds=1; done < <(server_listens "$sid")
        [[ $ds -eq 0 ]] && emit CFG-021 info "$(server_label "$sid") uses server_name _ without default_server" \
            "Add 'default_server' to make the catch-all explicit." ""
    done

    # CFG-022 slowloris timeouts
    local t
    for d in client_header_timeout client_body_timeout send_timeout; do
        for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
            v=$(effective_last "$sid" "$d") || true
            [[ -z $v ]] && continue
            t=$(parse_time_seconds "$v")
            (( t > 300 )) && emit CFG-022 warn "$(server_label "$sid") ${d} is ${v} (> 300s)" \
                "Lower client_header_timeout/client_body_timeout/send_timeout to limit slowloris." ""
        done
    done

    # CFG-023 oversized header buffers
    for sid in ${ALL_SERVERS[@]+"${ALL_SERVERS[@]}"}; do
        v=$(effective_last "$sid" large_client_header_buffers) || true
        [[ -z $v ]] && continue
        local sz=${v##* }
        m=$(parse_size_bytes "$sz")
        (( m > 32768 )) && emit CFG-023 warn "$(server_label "$sid") large_client_header_buffers size is $sz (> 32k)" \
            "Use 4 8k or similar; oversized buffers increase memory pressure." ""
    done
}

# ---------------------------------------------------------------------------
# Live probes and network checks
# ---------------------------------------------------------------------------
run_timeout() {
    if has_cmd timeout; then
        timeout "$OPT_TIMEOUT" "$@"
    else
        "$@"
    fi
}

probe_alpn() {
    local d=$1 out
    out=$(run_timeout openssl s_client -connect "$PROBE_HOST:$PROBE_PORT" \
        -servername "$d" -alpn h2 </dev/null 2>&1 | tr -d '\000') || true
    case $out in
        *"ALPN protocol: h2"*) printf 'h2' ;;
        *"No ALPN negotiated"*) printf 'none' ;;
        *"ALPN protocol: "*) sed -n 's/.*ALPN protocol: //p' <<< "$out" | head -n1 ;;
        *) printf 'error' ;;
    esac
}

probe_legacy() {
    local ver=$1 d=$2 out
    out=$(run_timeout openssl s_client -connect "$PROBE_HOST:$PROBE_PORT" \
        -servername "$d" -"$ver" -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | tr -d '\000') || true
    if grep -qE "(New, |Protocol[[:space:]]*: )${ver}([,[:space:]]|$)" <<< "$out" \
        && ! grep -q 'Cipher is (NONE)' <<< "$out"; then
        printf '1'
    else
        printf '0'
    fi
}

probe_cert() {
    local d=$1 pem
    pem=$(run_timeout openssl s_client -connect "$PROBE_HOST:$PROBE_PORT" \
        -servername "$d" </dev/null 2>/dev/null | openssl x509 -outform PEM 2>/dev/null) || true
    [[ -z $pem ]] && return 0
    if openssl x509 -help 2>&1 | grep -q -- '-checkhost'; then
        if openssl x509 -checkhost "$d" -noout <<< "$pem" >/dev/null 2>&1; then
            CERT_MATCH[$d]=1
        else
            CERT_MATCH[$d]=0
        fi
    fi
    if ! openssl x509 -checkend 0 -noout <<< "$pem" >/dev/null 2>&1; then
        CERT_STATE[$d]="expired"
    elif ! openssl x509 -checkend 2592000 -noout <<< "$pem" >/dev/null 2>&1; then
        CERT_STATE[$d]="expiring"
    else
        CERT_STATE[$d]="ok"
    fi
}

probe_server_header() {
    local d=$1 hdr
    has_cmd curl || return 0
    hdr=$(curl -skI --max-time "$OPT_TIMEOUT" --resolve "$d:$PROBE_PORT:$PROBE_HOST" \
        "https://$d:$PROBE_PORT/" 2>/dev/null) || true
    awk 'BEGIN{IGNORECASE=1} /^server:/{sub(/^[^:]*:[ \t]*/,""); sub(/\r$/,""); print; exit}' <<< "$hdr"
}

prepare_live() {
    local d first any=0
    LIVE_READY=0
    [[ $LIVE -eq 1 ]] || return 0
    if ! has_cmd openssl; then
        emit NET-006 skip "openssl not found; live TLS/ALPN probes skipped" "" ""
        LIVE=0
        return 0
    fi

    local -a doms=()
    mapfile -t doms < <(all_domains | head -n "$OPT_MAX_DOMAINS")
    [[ ${#doms[@]} -eq 0 ]] && doms=(localhost)
    first=${doms[0]}

    for d in ${doms[@]+"${doms[@]}"}; do
        ALPN_RESULT[$d]=$(probe_alpn "$d")
        [[ ${ALPN_RESULT[$d]} != error ]] && any=1
        probe_cert "$d"
    done

    LIVE_TLS10=$(probe_legacy tls1 "$first")
    LIVE_TLS11=$(probe_legacy tls1_1 "$first")
    LIVE_SERVER_HEADER=$(probe_server_header "$first")
    LIVE_READY=1

    if [[ $any -eq 0 ]]; then
        emit NET-006 info "TLS probes could not connect to ${PROBE_HOST}:${PROBE_PORT}" \
            "Check that nginx is listening and that --host/--port are correct." ""
    fi
}

check_network() {
    local listeners line laddr rest port info=""
    local nginx_seen=0 non_nginx=0 ipv6=0

    if [[ $MODE == "offline (dump)" ]]; then
        emit NET-001 skip "local listener inspection skipped for an offline dump" "" ""
    elif [[ $PROBE_HOST != "127.0.0.1" && $PROBE_HOST != "localhost" && $PROBE_HOST != "::1" ]]; then
        emit NET-001 skip "local listener inspection skipped for remote host $PROBE_HOST" "" ""
    else
        if has_cmd ss; then
            listeners=$(ss -H -tlnp 2>/dev/null || ss -H -tln 2>/dev/null) || true
        elif has_cmd netstat; then
            listeners=$(netstat -tlnp 2>/dev/null) || true
        else
            emit NET-001 skip "neither ss nor netstat is available" "" ""
            listeners=""
        fi
        while IFS= read -r line; do
            [[ -z $line ]] && continue
            read -r _ _ _ laddr _ rest <<< "$line"
            [[ ${laddr:-} == *:* ]] || continue
            port=${laddr##*:}
            [[ $port =~ ^[0-9]+$ ]] || continue
            [[ $port == 80 || $port == 443 ]] || continue
            info+=" ${port}/tcp"
            [[ $laddr == \[* ]] && ipv6=1
            if [[ -n ${rest:-} ]]; then
                if [[ $rest == *nginx* || $line == *nginx* ]]; then
                    nginx_seen=1
                else
                    non_nginx=1
                fi
            fi
        done <<< "$listeners"
        if [[ -n $listeners ]]; then
            emit NET-001 info "local listeners on 80/443:${info:- none}" "" ""
            if [[ $nginx_seen -eq 1 ]]; then
                emit NET-002 pass "nginx owns at least one listener on 80/443" "" ""
            else
                emit NET-002 warn "no nginx process was visible on the 80/443 listeners" \
                    "Another server may be bound to these ports, or process info is hidden (run as root)." ""
            fi
            [[ $non_nginx -eq 1 ]] && emit NET-003 info "a non-nginx process is visible on 80/443" \
                "Confirm that the expected process owns the public ports." ""
            [[ $ipv6 -eq 1 ]] && emit NET-005 info "at least one listener uses IPv6" "" ""
        fi
    fi

    if [[ $LIVE_READY -eq 1 && -n $LIVE_SERVER_HEADER ]]; then
        if [[ ${LIVE_SERVER_HEADER,,} == *nginx/* ]]; then
            emit NET-004 warn "the Server header reveals the nginx version: $LIVE_SERVER_HEADER" \
                "Set 'server_tokens off;' and consider hiding the Server header at the edge." ""
        fi
    fi
}

# ---------------------------------------------------------------------------
# Advisory table
# ---------------------------------------------------------------------------
# id|severity|feature|min|max|fixed|summary
CVE_DATA=(
"CVE-2026-123007|critical|http2|1.9.5|1.31.8|1.31.9,1.30.7|Memory corruption in HTTP/2 flow control"
"CVE-2026-123633|medium|http2|1.19.7|1.31.8|1.31.9,1.30.7|Use-after-free in HTTP/2"
"CVE-2026-121810|medium|http3|1.25.0|1.31.8|1.31.9,1.30.7|Use-after-free in HTTP/3"
"CVE-2026-118899|high|tls|1.13.0|1.31.8|1.31.9,1.30.7|Infinite loop reading a TLS 1.3 request body"
"CVE-2026-125283|medium|alias_try_files|0.9.6|1.31.8|1.31.9,1.30.7|Buffer overflow with alias and try_files"
"CVE-2026-15176|high|alias_rewrite|0.1.29|1.31.6|1.31.7,1.30.6|Buffer overflow with alias and rewrite"
"CVE-2026-97629|high|tls_tickets|1.23.2|1.31.6|1.31.7,1.30.6|Session forgery with TLS session tickets"
"CVE-2026-95101|medium|http3|1.25.0|1.31.6|1.31.7,1.30.6|Request body injection in HTTP/3"
"CVE-2026-97205|medium|aio|0.8.11|1.31.6|1.31.7,1.30.6|Use-after-free with asynchronous file I/O"
"CVE-2026-90439|medium|http3|1.29.2|1.31.5|1.31.6,1.30.5|Buffer overflow in the HTTP/3 module"
"CVE-2026-42533|critical|map_regex|0.9.6|1.31.2|1.31.3,1.30.4|Buffer overflow with map and regex"
"CVE-2026-60005|medium|slice|1.15.8|1.31.2|1.31.3,1.30.4|Memory disclosure in the slice module"
"CVE-2026-56434|medium|ssi|0.8.11|1.31.2|1.31.3,1.30.4|Use-after-free in the SSI module"
"CVE-2026-42530|high|http3|1.31.0|1.31.1|1.31.2|Use-after-free in HTTP/3"
"CVE-2026-42055|medium|grpc|1.13.10|1.31.1|1.31.2,1.30.3|Buffer overflow in proxy_v2/grpc modules"
"CVE-2026-9256|medium|rewrite|0.1.17|1.31.0|1.31.1,1.30.2|Buffer overflow in the rewrite module"
"CVE-2026-42926|medium|http2_proxy|1.29.4|1.30.0|1.31.0,1.30.1|HTTP/2 request injection via the proxy module"
"CVE-2026-42945|medium|rewrite|0.6.27|1.30.0|1.31.0,1.30.1|Buffer overflow in the rewrite module"
"CVE-2026-42946|medium|scgi_uwsgi|0.8.42|1.30.0|1.31.0,1.30.1|Buffer overread in SCGI/uWSGI modules"
"CVE-2026-40460|medium|http3|1.25.0|1.30.0|1.31.0,1.30.1|HTTP/3 address spoofing"
"CVE-2026-40701|medium|ocsp|1.19.0|1.30.0|1.31.0,1.30.1|Resolver use-after-free in OCSP"
"CVE-2026-27654|medium|dav|0.5.13|1.29.6|1.29.7,1.28.3|Buffer overflow in the DAV module"
"CVE-2026-28753|medium|auth_http|0.6.27|1.29.6|1.29.7,1.28.3|Injection in auth_http and XCLIENT"
"CVE-2025-23419|medium|tls|1.11.4|1.27.3|1.27.4,1.26.3|TLS session reuse vulnerability"
"CVE-2024-7347|low|mp4|1.5.13|1.27.0|1.27.1,1.26.2|Buffer overread in the mp4 module"
"CVE-2024-24990|high|http3|1.25.0|1.25.3|1.25.4|Use-after-free in HTTP/3"
"CVE-2021-23017|medium|resolver|0.6.18|1.20.0|1.21.0,1.20.1|1-byte memory overwrite in the resolver"
"CVE-2019-9511|high|http2|1.9.5|1.17.2|1.17.3,1.16.1|HTTP/2 DoS via small window updates"
"CVE-2019-9513|medium|http2|1.9.5|1.17.2|1.17.3,1.16.1|HTTP/2 DoS via priority changes"
"CVE-2018-16843|medium|http2|1.9.5|1.15.5|1.15.6,1.14.1|HTTP/2 memory exhaustion"
"CVE-2018-16844|medium|http2|1.9.5|1.15.5|1.15.6,1.14.1|HTTP/2 CPU exhaustion"
"CVE-2017-7529|medium|range|0.5.6|1.13.2|1.13.3,1.12.1|Integer overflow in the range filter"
)

register_cve_checks() {
    local row id sev feat min max fixes summary
    for row in "${CVE_DATA[@]}"; do
        IFS='|' read -r id sev feat min max fixes summary <<< "$row"
        register_check "$id" "$sev" "$summary"
    done
}

feat_http2() { [[ $HTTP2_ENABLED -eq 1 ]]; }

feat_http3() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == http3 && ${L_ARGS[i]} == on ]] && return 0
        [[ ${L_DIR[i]} == listen ]] && has_word "${L_ARGS[i]}" quic && return 0
    done
    return 1
}

feat_tls() { [[ ${#TLS_SERVERS[@]} -gt 0 ]]; }

feat_alias_try_files() {
    local i lid
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == alias ]] || continue
        lid=${L_LID[i]}
        ctx_has_dir "$lid" try_files && return 0
    done
    return 1
}

feat_alias_rewrite() {
    local i lid
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == alias ]] || continue
        lid=${L_LID[i]}
        ctx_has_dir "$lid" rewrite && return 0
    done
    return 1
}

feat_tls_tickets() {
    local sid v
    for sid in ${TLS_SERVERS[@]+"${TLS_SERVERS[@]}"}; do
        v=$(effective_last "$sid" ssl_session_tickets) || true
        [[ $v != off ]] && return 0
    done
    return 1
}

feat_aio() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == aio && ${L_ARGS[i]} != off ]] && return 0
    done
    return 1
}

feat_map_regex() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_CTX[i]} == *">map"* ]] || continue
        [[ ${L_DIR[i]} == "~"* ]] && return 0
    done
    return 1
}

feat_slice() { [[ $(count_dir slice) -gt 0 ]]; }

feat_ssi() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == ssi && ${L_ARGS[i]} == on ]] && return 0
    done
    return 1
}

feat_grpc() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == grpc_pass ]] && return 0
        [[ ${L_DIR[i]} == proxy_pass && ${L_ARGS[i]} == *"grpc://"* ]] && return 0
    done
    return 1
}

feat_rewrite() { [[ $(count_dir rewrite) -gt 0 ]]; }

feat_scgi_uwsgi() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == scgi_pass || ${L_DIR[i]} == uwsgi_pass ]] && return 0
    done
    return 1
}

feat_ocsp() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == ssl_stapling && ${L_ARGS[i]} == on ]] && return 0
    done
    return 1
}

feat_dav() {
    local i
    for ((i=0;i<CFG_N;i++)); do
        [[ ${L_DIR[i]} == dav_methods && ${L_ARGS[i]} != off ]] && return 0
    done
    return 1
}

feat_mp4() { [[ $(count_dir mp4) -gt 0 ]]; }
feat_resolver() { [[ $(count_dir resolver) -gt 0 ]]; }
feat_auth_http() { [[ $(count_dir auth_http) -gt 0 ]]; }
feat_range() { return 0; }

feat_http2_proxy() {
    [[ $HTTP2_ENABLED -eq 1 ]] || return 1
    [[ $(count_dir proxy_pass) -gt 0 ]]
}

feature_enabled() {
    local f=$1
    if declare -F "feat_$f" >/dev/null 2>&1; then
        "feat_$f"
    else
        return 0
    fi
}

check_cves() {
    local row id sev feat min max fixes summary
    [[ -z $NGINX_VERSION ]] && return 0
    for row in "${CVE_DATA[@]}"; do
        IFS='|' read -r id sev feat min max fixes summary <<< "$row"
        feature_enabled "$feat" || continue
        version_vulnerable "$NGINX_VERSION" "$min" "$max" "$fixes" || continue
        emit "$id" fail "nginx/$NGINX_VERSION is affected by $id: $summary (feature in use: $feat; fixed in $fixes)" \
            "Upgrade to nginx $fixes or later, or disable the affected feature." \
            "https://nginx.org/en/security_advisories.html"
    done
}

# ---------------------------------------------------------------------------
# Summary and output
# ---------------------------------------------------------------------------
CNT_CRIT=0; CNT_HIGH=0; CNT_MED=0; CNT_LOW=0; CNT_INFO=0
CNT_PASS=0; CNT_SKIP=0
EXIT_CODE=0

compute_summary() {
    local i
    CNT_CRIT=0; CNT_HIGH=0; CNT_MED=0; CNT_LOW=0; CNT_INFO=0
    CNT_PASS=0; CNT_SKIP=0
    for i in "${!F_ID[@]}"; do
        case ${F_ST[i]} in
            pass) CNT_PASS=$((CNT_PASS + 1)); continue ;;
            skip) CNT_SKIP=$((CNT_SKIP + 1)); continue ;;
            info) CNT_INFO=$((CNT_INFO + 1)); continue ;;
        esac
        case ${F_SEV[i]} in
            critical) CNT_CRIT=$((CNT_CRIT + 1)) ;;
            high)     CNT_HIGH=$((CNT_HIGH + 1)) ;;
            medium)   CNT_MED=$((CNT_MED + 1)) ;;
            low)      CNT_LOW=$((CNT_LOW + 1)) ;;
            *)        CNT_INFO=$((CNT_INFO + 1)) ;;
        esac
    done
}

compute_exit() {
    local i thr
    EXIT_CODE=0
    thr=$(sev_rank "$OPT_FAIL_ON")
    for i in "${!F_ID[@]}"; do
        case ${F_ST[i]} in
            fail|warn|info) ;;
            *) continue ;;
        esac
        if (( $(sev_rank "${F_SEV[i]}") >= thr )); then
            EXIT_CODE=1
        fi
    done
}

print_text() {
    local i sev label color minrank
    minrank=$(sev_rank "$OPT_MIN_SEV")

    if [[ $OPT_QUIET -eq 0 ]]; then
        printf '%s%s%s %s - nginx HTTP/2 + privilege audit\n' "$C_BOLD" "$PROG" "$C_RESET" "$VERSION"
        printf 'config: %s' "${CONFIG_MAIN:-unknown}"
        [[ -n $NGINX_VERSION ]] && printf ' (nginx/%s)' "$NGINX_VERSION"
        printf '  mode: %s' "${MODE:-unknown}"
        [[ $LIVE -eq 1 ]] && printf '  probe: %s:%s' "$PROBE_HOST" "$PROBE_PORT"
        printf '\n\n'
    fi

    for sev in critical high medium low info; do
        for i in "${!F_ID[@]}"; do
            [[ ${F_SEV[i]} == "$sev" ]] || continue
            case ${F_ST[i]} in
                fail|warn|info) ;;
                *) continue ;;
            esac
            [[ $OPT_QUIET -eq 1 && ${F_ST[i]} == info ]] && continue
            (( $(sev_rank "$sev") < minrank )) && continue

            case ${F_ST[i]} in
                fail) label=$(sev_label "$sev"); color=$(sev_color "$sev") ;;
                warn) label="WARN"; color=$C_YELLOW ;;
                *)    label="INFO"; color=$C_DIM ;;
            esac
            printf '%s%-6s%s %-10s %s\n' "$color" "$label" "$C_RESET" "${F_ID[i]}" "${F_TITLE[i]}"
            [[ -n ${F_DETAIL[i]} ]] && printf '       %s\n' "${F_DETAIL[i]}"
            [[ -n ${F_FIX[i]} ]] && printf '       %sfix:%s %s\n' "$C_DIM" "$C_RESET" "${F_FIX[i]}"
            [[ -n ${F_REF[i]} ]] && printf '       %sref:%s %s\n' "$C_DIM" "$C_RESET" "${F_REF[i]}"
        done
    done

    if [[ $OPT_VERBOSE -eq 1 ]]; then
        printf '\n%sPassed / skipped%s\n' "$C_BOLD" "$C_RESET"
        for i in "${!F_ID[@]}"; do
            case ${F_ST[i]} in
                pass) printf '%s ok %s %-10s %s\n' "$C_GREEN" "$C_RESET" "${F_ID[i]}" "${F_DETAIL[i]:-${F_TITLE[i]}}" ;;
                skip) printf '%sskip%s %-10s %s\n' "$C_DIM" "$C_RESET" "${F_ID[i]}" "${F_DETAIL[i]:-${F_TITLE[i]}}" ;;
            esac
        done
    fi

    if [[ $OPT_QUIET -eq 0 ]]; then
        printf '\nSummary: %d critical, %d high, %d medium, %d low, %d info | %d passed, %d skipped\n' \
            "$CNT_CRIT" "$CNT_HIGH" "$CNT_MED" "$CNT_LOW" "$CNT_INFO" "$CNT_PASS" "$CNT_SKIP"
        if [[ $EXIT_CODE -eq 0 ]]; then
            printf '%sResult: PASS%s (fail-on: %s)\n' "$C_GREEN" "$C_RESET" "$OPT_FAIL_ON"
        else
            printf '%sResult: FAIL%s (fail-on: %s)\n' "$C_RED" "$C_RESET" "$OPT_FAIL_ON"
        fi
    fi
}

print_json() {
    local i sep="" probe_json="null"
    [[ $LIVE -eq 1 ]] && probe_json="\"$(json_escape "$PROBE_HOST:$PROBE_PORT")\""
    printf '{\n'
    printf '  "tool": "nginx2root",\n'
    printf '  "version": "%s",\n' "$(json_escape "$VERSION")"
    printf '  "generated_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "target": {\n'
    printf '    "config": "%s",\n' "$(json_escape "$CONFIG_MAIN")"
    printf '    "nginx_version": "%s",\n' "$(json_escape "$NGINX_VERSION")"
    printf '    "mode": "%s",\n' "$(json_escape "$MODE")"
    printf '    "probe": %s\n' "$probe_json"
    printf '  },\n'
    printf '  "summary": {\n'
    printf '    "critical": %d,\n' "$CNT_CRIT"
    printf '    "high": %d,\n' "$CNT_HIGH"
    printf '    "medium": %d,\n' "$CNT_MED"
    printf '    "low": %d,\n' "$CNT_LOW"
    printf '    "info": %d,\n' "$CNT_INFO"
    printf '    "passed": %d,\n' "$CNT_PASS"
    printf '    "skipped": %d,\n' "$CNT_SKIP"
    printf '    "findings": %d,\n' "$((CNT_CRIT + CNT_HIGH + CNT_MED + CNT_LOW + CNT_INFO))"
    printf '    "exit_code": %d\n' "$EXIT_CODE"
    printf '  },\n'
    printf '  "findings": ['
    for i in "${!F_ID[@]}"; do
        printf '%s\n    {' "$sep"
        printf '"id":"%s","severity":"%s","status":"%s","title":"%s","detail":"%s","fix":"%s","ref":"%s"}' \
            "$(json_escape "${F_ID[i]}")" \
            "$(json_escape "${F_SEV[i]}")" \
            "$(json_escape "${F_ST[i]}")" \
            "$(json_escape "${F_TITLE[i]}")" \
            "$(json_escape "${F_DETAIL[i]}")" \
            "$(json_escape "${F_FIX[i]}")" \
            "$(json_escape "${F_REF[i]}")"
        sep=","
    done
    printf '\n  ]\n}\n'
}

# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------
self_test() {
    local failures=0
    st_eq() {
        local desc=$1 exp=$2 act=$3
        if [[ $act == "$exp" ]]; then
            printf 'ok   %s\n' "$desc"
        else
            printf 'FAIL %s (expected %q, got %q)\n' "$desc" "$exp" "$act"
            failures=$((failures + 1))
        fi
    }
    st_true() {
        local desc=$1; shift
        if "$@"; then printf 'ok   %s\n' "$desc"
        else printf 'FAIL %s (returned false)\n' "$desc"; failures=$((failures + 1)); fi
    }
    st_false() {
        local desc=$1; shift
        if "$@"; then printf 'FAIL %s (returned true)\n' "$desc"; failures=$((failures + 1))
        else printf 'ok   %s\n' "$desc"; fi
    }

    st_true  "ver_ge equal" ver_ge 1.31.9 1.31.9
    st_false "ver_ge older" ver_ge 1.30.7 1.31.9
    st_true  "fixed same stable branch" version_fixed 1.30.7 "1.31.9,1.30.7"
    st_false "not fixed on mainline branch" version_fixed 1.31.0 "1.31.9,1.30.7"
    st_true  "fixed above max" version_fixed 1.32.0 "1.31.9,1.30.7"
    st_false "not fixed old stable" version_fixed 1.24.0 "1.25.4"
    st_true  "fixed newer mainline" version_fixed 1.26.0 "1.25.4"
    st_true  "vulnerable 1.31.8" version_vulnerable 1.31.8 1.9.5 1.31.8 "1.31.9,1.30.7"
    st_false "fixed 1.31.9" version_vulnerable 1.31.9 1.9.5 1.31.8 "1.31.9,1.30.7"
    st_false "fixed 1.30.7" version_vulnerable 1.30.7 1.9.5 1.31.8 "1.31.9,1.30.7"
    st_true  "vulnerable 1.30.6" version_vulnerable 1.30.6 1.9.5 1.31.8 "1.31.9,1.30.7"
    st_eq "time 5m" "300" "$(parse_time_seconds 5m)"
    st_eq "time 60s" "60" "$(parse_time_seconds 60s)"
    st_eq "size 8k" "8192" "$(parse_size_bytes 8k)"
    st_eq "size 1m" "1048576" "$(parse_size_bytes 1m)"
    st_eq "clean cipher list" "" "$(weak_ciphers 'HIGH:!aNULL:!MD5')"
    st_eq "weak cipher list" " RC4-SHA" "$(weak_ciphers 'RC4-SHA')"

    if (( failures > 0 )); then
        printf '\n%d self-test(s) failed\n' "$failures"
        return 1
    fi
    printf '\nall self-tests passed\n'
    return 0
}

# ---------------------------------------------------------------------------
# Argument parsing and main
# ---------------------------------------------------------------------------
SHOW_CHECKS=0
SHOW_CVES=0
RUN_SELFTEST=0

parse_args() {
    while (( $# > 0 )); do
        case $1 in
            -c|--config) [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_CONFIG=$2; shift 2 ;;
            -T|--dump)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_DUMP=$2; shift 2 ;;
            --nginx-version) [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_NGINX_VERSION=$2; shift 2 ;;
            -H|--host)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_HOST=$2; shift 2 ;;
            -p|--port)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_PORT=$2; shift 2 ;;
            --timeout)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_TIMEOUT=$2; shift 2 ;;
            --max-domains) [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_MAX_DOMAINS=$2; shift 2 ;;
            --only)      [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_ONLY=$2; shift 2 ;;
            --exclude)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_EXCLUDE=$2; shift 2 ;;
            --fail-on)   [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_FAIL_ON=$2; shift 2 ;;
            --min-severity) [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_MIN_SEV=$2; shift 2 ;;
            --format)    [[ $# -ge 2 ]] || die 2 "$1 requires a value"; OPT_FORMAT=$2; shift 2 ;;
            --json)      OPT_FORMAT=json; shift ;;
            --no-color)  OPT_NO_COLOR=1; shift ;;
            --no-live)   OPT_LIVE=0; shift ;;
            --live)      OPT_LIVE=1; shift ;;
            --no-sudo)   OPT_SUDO=0; shift ;;
            -q|--quiet)  OPT_QUIET=1; shift ;;
            -v|--verbose) OPT_VERBOSE=1; shift ;;
            --list-checks) SHOW_CHECKS=1; shift ;;
            --list-cves) SHOW_CVES=1; shift ;;
            --self-test) RUN_SELFTEST=1; shift ;;
            -V|--version) printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            --) shift; break ;;
            -*) die 2 "unknown option: $1 (try --help)" ;;
            *) die 2 "unexpected argument: $1 (try --help)" ;;
        esac
    done

    case $OPT_FORMAT in text|json) ;; *) die 2 "--format must be text or json" ;; esac
    case $OPT_FAIL_ON in critical|high|medium|low|info|none) ;; *) die 2 "--fail-on must be critical|high|medium|low|info|none" ;; esac
    case $OPT_MIN_SEV in critical|high|medium|low|info) ;; *) die 2 "--min-severity must be critical|high|medium|low|info" ;; esac
    if [[ -n $OPT_NGINX_VERSION && ! $OPT_NGINX_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        die 2 "--nginx-version must look like 1.31.9"
    fi
    [[ $OPT_PORT =~ ^[0-9]+$ ]] && (( OPT_PORT >= 1 && OPT_PORT <= 65535 )) || die 2 "--port must be 1-65535"
    [[ $OPT_TIMEOUT =~ ^[0-9]+$ ]] && (( OPT_TIMEOUT >= 1 )) || die 2 "--timeout must be a positive integer"
    [[ $OPT_MAX_DOMAINS =~ ^[0-9]+$ ]] && (( OPT_MAX_DOMAINS >= 1 )) || die 2 "--max-domains must be a positive integer"
    PROBE_HOST=$OPT_HOST
    PROBE_PORT=$OPT_PORT
}

main() {
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        die 2 "bash 4.4 or newer is required (found $BASH_VERSION)"
    fi
    parse_args "$@"
    init_colors
    register_all_checks
    register_cve_checks

    if [[ $SHOW_CHECKS -eq 1 ]]; then
        {
            for id in "${!CHECK_SEV[@]}"; do
                printf '%-16s %-8s %s\n' "$id" "${CHECK_SEV[$id]}" "${CHECK_TITLE[$id]}"
            done
        } | sort
        exit 0
    fi
    if [[ $SHOW_CVES -eq 1 ]]; then
        printf '%-18s %-8s %-16s %s\n' "ID" "SEVERITY" "FEATURE" "SUMMARY"
        for row in "${CVE_DATA[@]}"; do
            IFS='|' read -r id sev feat min max fixes summary <<< "$row"
            printf '%-18s %-8s %-16s %s\n' "$id" "$sev" "$feat" "$summary"
        done
        exit 0
    fi
    if [[ $RUN_SELFTEST -eq 1 ]]; then
        self_test
        exit $?
    fi

    N2R_TMP=$(mktemp -d "${TMPDIR:-/tmp}/nginx2root.XXXXXX") || die 2 "could not create a temporary directory"
    setup_parser
    acquire_config
    LIVE=$OPT_LIVE
    load_config

    if (( CFG_N == 0 )); then
        die 3 "the configuration parsed to zero directives"
    fi

    detect_version || true
    detect_servers
    detect_http2
    detect_tls_servers
    detect_runtime
    resolve_worker_user
    prepare_live

    check_env
    check_http2
    check_tls
    check_privileges
    check_config
    check_network
    check_cves

    compute_summary
    compute_exit

    if [[ $OPT_FORMAT == json ]]; then
        print_json
    else
        print_text
    fi
    exit "$EXIT_CODE"
}

main "$@"
