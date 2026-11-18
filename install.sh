#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Install nginx2root into PREFIX/bin (default /usr/local/bin).
set -euo pipefail

PROG=nginx2root
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PREFIX=${PREFIX:-/usr/local}
BINDIR=${BINDIR:-$PREFIX/bin}
MANDIR=${MANDIR:-$PREFIX/share/man/man1}
DESTDIR=${DESTDIR:-}
WITH_MAN=1
UNINSTALL=0

usage() {
    cat <<'USAGE'
Usage: install.sh [options]

Options:
  --prefix PATH     install prefix (default /usr/local)
  --bindir PATH     binary directory (default PREFIX/bin)
  --no-man          do not install the man page
  --uninstall       remove installed files
  -h, --help        show this help

Environment:
  PREFIX, BINDIR, MANDIR, DESTDIR

Examples:
  sudo ./install.sh
  PREFIX=$HOME/.local ./install.sh
  DESTDIR=/tmp/pkg ./install.sh
USAGE
}

while (( $# > 0 )); do
    case $1 in
        --prefix) [[ $# -ge 2 ]] || { echo "--prefix requires a value" >&2; exit 2; }; PREFIX=$2; BINDIR=${BINDIR:-$PREFIX/bin}; MANDIR=${MANDIR:-$PREFIX/share/man/man1}; shift 2 ;;
        --bindir) [[ $# -ge 2 ]] || { echo "--bindir requires a value" >&2; exit 2; }; BINDIR=$2; shift 2 ;;
        --no-man) WITH_MAN=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

target="$DESTDIR$BINDIR"
man_target="$DESTDIR$MANDIR"

if [[ $UNINSTALL -eq 1 ]]; then
    rm -f "$target/$PROG"
    rm -f "$man_target/$PROG.1"
    echo "removed $target/$PROG"
    exit 0
fi

if ! install -d "$target"; then
    echo "cannot create $target; re-run with sudo or set PREFIX=\$HOME/.local" >&2
    exit 1
fi
install -m 0755 "$SCRIPT_DIR/nginx2root.sh" "$target/$PROG"
echo "installed $target/$PROG"

if [[ $WITH_MAN -eq 1 && -f "$SCRIPT_DIR/docs/nginx2root.1" ]]; then
    install -d "$man_target"
    install -m 0644 "$SCRIPT_DIR/docs/nginx2root.1" "$man_target/$PROG.1"
    echo "installed $man_target/$PROG.1"
fi

echo "run: $PROG --help"
