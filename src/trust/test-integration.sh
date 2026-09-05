#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

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
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.05; done
[ -S "$SOCK" ] || { echo "FAIL: Varlink socket was not created"; exit 1; }

fail() { echo "FAIL: $*"; exit 1; }

if command -v varlinkctl >/dev/null 2>&1; then
        vc() { varlinkctl call "$SOCK" "io.platformd.Trust.$1" "$2" 2>&1; }

        R=$(vc GetBootEvidence '{}') || fail "GetBootEvidence errored: $R"
        echo "$R" | grep -q '"bootId"' || fail "GetBootEvidence has no bootId: $R"
        echo "$R" | grep -q '"evidenceQuality"' || fail "GetBootEvidence has no evidenceQuality"

        R=$(vc GetMeasuredBoot '{}') || fail "GetMeasuredBoot errored: $R"
        echo "$R" | grep -q '"bootQuality"' || fail "GetMeasuredBoot has no bootQuality: $R"

        R=$(vc ListSessions '{}') || fail "ListSessions errored: $R"
        echo "$R" | grep -q '"sessions"' || fail "ListSessions has no sessions array: $R"

        # An unknown session is always denied.
        R=$(vc EvaluatePolicy '{"policy":"local-trusted-session","sessionId":"no-such-xyz"}') \
                || fail "EvaluatePolicy(unknown session) errored: $R"
        echo "$R" | grep -q 'denied' || fail "unknown session was not denied: $R"
        echo "$R" | grep -q '"reasonCode":"session-not-found"' \
                || fail "unknown session has no stable reason code: $R"

        # An unknown policy is a clean Varlink error, not a crash.
        if vc EvaluatePolicy '{"policy":"totally-bogus","sessionId":"x"}' >/dev/null 2>&1; then
                fail "unknown policy did not error"
        fi
        R=$(vc EvaluatePolicy '{"policy":"totally-bogus","sessionId":"x"}')
        echo "$R" | grep -q 'UnknownPolicy' || fail "unknown policy: wrong error: $R"

        R=$(vc GetUserIdentity '{"uid":0}') || fail "GetUserIdentity errored: $R"
        echo "$R" | grep -q '"userName"' || fail "GetUserIdentity has no userName: $R"

        # The test environment has no TPM backend, including for a root caller.
        R=$(vc Attest '{"nonceHex":"deadbeef"}' || true)
        if [ "$(id -u)" = "0" ]; then
                echo "$R" | grep -qE 'AttestationUnsupported|AttestationFailed' \
                        || fail "Attest (root) did not reject the unavailable TPM: $R"
        else
                echo "$R" | grep -q 'PermissionDenied' \
                        || fail "Attest from a non-root caller was not refused: $R"
        fi

        R=$(vc GetRuntimeLog '{}') || fail "GetRuntimeLog errored: $R"
        echo "$R" | grep -q '"nvIndex"' || fail "GetRuntimeLog has no nvIndex: $R"
        echo "$R" | grep -q '"complete"' || fail "GetRuntimeLog has no completeness flag: $R"

        # Event submission is root-only. Confirm an unprivileged caller is rejected.
        SUBMIT='{"user":"x","uid":1,"pamService":"t","tty":"","remoteHost":"","phase":"session","declaredMethod":"password","result":"success","sessionId":"1"}'
        if [ "$(id -u)" = "0" ]; then
                if command -v setpriv >/dev/null 2>&1; then
                        if setpriv --reuid=65534 --regid=65534 --clear-groups \
                                varlinkctl call "$SOCK" io.platformd.Trust.SubmitAuthEvent "$SUBMIT" >/dev/null 2>&1; then
                                fail "SubmitAuthEvent from an unprivileged uid was accepted"
                        fi
                fi
        else
                if vc SubmitAuthEvent "$SUBMIT" >/dev/null 2>&1; then
                        fail "SubmitAuthEvent from a non-root caller was accepted"
                fi
        fi

        echo "OK: Varlink surface + error paths (boot/measured/sessions/verdict/policy/identity/attest/runtime/root-gate)"
else
        echo "SKIP: varlinkctl unavailable; Varlink-surface checks skipped"
fi

# trustctl reader commands must all succeed against the running daemon.
"$TRUSTCTL" status | grep -q "^Boot:" || fail "trustctl status: no boot evidence"
for cmd in pcrs list-sessions events runtime-log; do
        "$TRUSTCTL" "$cmd" >/dev/null 2>&1 || fail "trustctl $cmd errored"
done

# Boot references are keyed independently. Removing one must not remove another.
REFSTATE="$PLATFORMD_TRUSTD_RUNTIME/state"
mkdir -p "$REFSTATE/boot-references"
printf '%s\n' '{"pcrBank":"sha256","pcr11":["aa"],"referenceId":"first"}' \
        > "$REFSTATE/boot-references/first.json"
printf '%s\n' '{"pcrBank":"sha256","pcr11":["bb"],"referenceId":"second"}' \
        > "$REFSTATE/boot-references/second.json"
PLATFORMD_TRUSTD_STATE="$REFSTATE" "$TRUSTCTL" remove-boot-reference first \
        || fail "remove-boot-reference failed"
[ ! -e "$REFSTATE/boot-references/first.json" ] \
        || fail "remove-boot-reference retained the selected reference"
[ -e "$REFSTATE/boot-references/second.json" ] \
        || fail "remove-boot-reference removed another reference"
if PLATFORMD_TRUSTD_STATE="$REFSTATE" "$TRUSTCTL" remove-boot-reference '../invalid' >/dev/null 2>&1; then
        fail "remove-boot-reference accepted an invalid identifier"
fi

echo "OK: integration test passed"
