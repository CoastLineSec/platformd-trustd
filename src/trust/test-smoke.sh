#!/bin/sh
# T1 smoke test: the daemon starts, serves io.platformd.Trust, and trustctl
# reads boot evidence and the session list. Runs without root or a live logind
# session (0 sessions is a valid result).
set -e

TRUSTD="$1"
TRUSTCTL="$2"
PLATFORMD_TRUSTD_RUNTIME="$(mktemp -d)"
export PLATFORMD_TRUSTD_RUNTIME
SOCK="$PLATFORMD_TRUSTD_RUNTIME/io.platformd.Trust"

"$TRUSTD" >/dev/null 2>&1 &
PID=$!
trap 'kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$PLATFORMD_TRUSTD_RUNTIME"' EXIT

i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do
        i=$((i + 1))
        sleep 0.05
done
[ -S "$SOCK" ] || { echo "FAIL: Varlink socket was not created"; exit 1; }

OUT="$("$TRUSTCTL" status 2>&1)" || { echo "FAIL: trustctl status errored"; echo "$OUT"; exit 1; }
echo "$OUT"
echo "$OUT" | grep -q "^Boot:" || { echo "FAIL: no boot evidence in status output"; exit 1; }

"$TRUSTCTL" list-sessions >/dev/null 2>&1 || { echo "FAIL: trustctl list-sessions errored"; exit 1; }

echo "OK: daemon serves io.platformd.Trust; trustctl reads boot evidence + sessions"
