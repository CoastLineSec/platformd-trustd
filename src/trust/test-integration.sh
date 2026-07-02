#!/bin/sh
# Integration test: exercise the io.platformd.Trust Varlink surface and its error
# paths. Designed to pass with no root, no TPM, no logind session, and no homed —
# the daemon degrades gracefully (observed evidence, empty session list,
# attestation unsupported) while the error paths (unknown policy, non-root event
# submission) still behave correctly. Anything the daemon can only do with a TPM
# or a live session is validated by hand under run0; here we validate the surface.
set -u

TRUSTD="$1"
TRUSTCTL="$2"
PLATFORMD_TRUSTD_RUNTIME="$(mktemp -d)"
export PLATFORMD_TRUSTD_RUNTIME
SOCK="$PLATFORMD_TRUSTD_RUNTIME/io.platformd.Trust"

"$TRUSTD" >/dev/null 2>&1 &
PID=$!
trap 'kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$PLATFORMD_TRUSTD_RUNTIME"' EXIT

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

        # A verdict on an unknown session is 'denied' — never crashes, never satisfied.
        R=$(vc EvaluatePolicy '{"policy":"local-trusted-session","sessionId":"no-such-xyz"}') \
                || fail "EvaluatePolicy(unknown session) errored: $R"
        echo "$R" | grep -q 'denied' || fail "unknown session was not denied: $R"

        # An unknown policy is a clean Varlink error, not a crash.
        if vc EvaluatePolicy '{"policy":"totally-bogus","sessionId":"x"}' >/dev/null 2>&1; then
                fail "unknown policy did not error"
        fi
        R=$(vc EvaluatePolicy '{"policy":"totally-bogus","sessionId":"x"}')
        echo "$R" | grep -q 'UnknownPolicy' || fail "unknown policy: wrong error: $R"

        R=$(vc GetUserIdentity '{"uid":0}') || fail "GetUserIdentity errored: $R"
        echo "$R" | grep -q '"userName"' || fail "GetUserIdentity has no userName: $R"

        # Attestation without a TPM: a clean error (or a quote if a TPM is present).
        R=$(vc Attest '{"nonceHex":"deadbeef"}' || true)
        echo "$R" | grep -qE 'quotedHex|AttestationUnsupported|AttestationFailed' \
                || fail "Attest neither quoted nor errored cleanly: $R"

        R=$(vc GetRuntimeLog '{}') || fail "GetRuntimeLog errored: $R"
        echo "$R" | grep -q '"nvIndex"' || fail "GetRuntimeLog has no nvIndex: $R"

        # Event submission is root-only. Confirm an unprivileged caller is rejected.
        SUBMIT='{"user":"x","uid":1,"pamService":"t","tty":"","remoteHost":"","phase":"open_session","declaredMethod":"password","result":"success","sessionId":"1"}'
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

echo "OK: integration test passed"
