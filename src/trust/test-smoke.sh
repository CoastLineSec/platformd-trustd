#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

if [ "${1:-}" != "--test-inner" ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

TRUSTD="$1"
TRUSTCTL="$2"
PLATFORMD_TRUSTD_RUNTIME="$(mktemp -d)"
SOCK="$PLATFORMD_TRUSTD_RUNTIME/io.platformd.Trust"
PLATFORMD_TRUST_SOCKET="$SOCK"
export PLATFORMD_TRUSTD_RUNTIME PLATFORMD_TRUST_SOCKET

timeout 1 "$TRUSTD" --help | grep -q platformd-trustd
timeout 1 "$TRUSTD" --version | grep -q platformd-trustd
if timeout 1 "$TRUSTD" --invalid-option >/dev/null 2>&1; then
        exit 1
fi
[ ! -e "$SOCK" ]
"$TRUSTD" >/dev/null 2>&1 &
PID=$!
cleanup() {
        kill -TERM "$PID" 2>/dev/null || :
        wait "$PID" 2>/dev/null || :
        rm -rf -- "$PLATFORMD_TRUSTD_RUNTIME"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do
        i=$((i + 1))
        sleep 0.05
done
[ -S "$SOCK" ] || { echo "FAIL: Varlink socket was not created"; exit 1; }
varlinkctl info "$SOCK" | grep -q platformd-trustd
normalize_idl() {
        awk '
                { sub(/#.*/, "") }
                /^[[:space:]]*(interface|type|method|error)[[:space:]]/ { if (s != "") print s; s = "" }
                { gsub(/[[:space:]]/, ""); s = s $0 }
                END { if (s != "") print s }
        ' | sort
}
published=$(varlinkctl introspect "$SOCK" io.platformd.Trust | normalize_idl)
expected=$(normalize_idl < "$(dirname "$0")/io.platformd.Trust.varlink")
[ "$published" = "$expected" ]
inode=$(stat -c %i "$SOCK")
if "$TRUSTD" >/dev/null 2>&1; then
        echo 'FAIL: duplicate daemon accepted'
        exit 1
fi
[ "$(stat -c %i "$SOCK")" = "$inode" ]

OUT="$("$TRUSTCTL" status 2>&1)" || { echo "FAIL: trustctl status errored"; echo "$OUT"; exit 1; }
echo "$OUT"
echo "$OUT" | grep -q "^Boot:" || { echo "FAIL: no boot evidence in status output"; exit 1; }

"$TRUSTCTL" list-sessions >/dev/null 2>&1 || { echo "FAIL: trustctl list-sessions errored"; exit 1; }

echo "OK: daemon serves io.platformd.Trust; trustctl reads boot evidence + sessions"
