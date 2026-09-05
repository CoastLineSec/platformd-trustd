#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != "--test-inner" ]; then
    exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ "${1:-}" = "--check-environment" ]; then
    test_root=${XDG_RUNTIME_DIR%/runtime}
    case "$test_root" in
        /tmp/platformd-test.??????) ;;
        *) fail "runtime directory is not private" ;;
    esac
    [ "$XDG_RUNTIME_DIR" = "$test_root/runtime" ] || fail "runtime directory changed"
    [ "$XDG_DATA_HOME" = "$test_root/data" ] || fail "data directory changed"
    [ "$XDG_CONFIG_HOME" = "$test_root/config" ] || fail "configuration directory changed"
    [ "$XDG_CACHE_HOME" = "$test_root/cache" ] || fail "cache directory changed"
    [ "$XDG_STATE_HOME" = "$test_root/state" ] || fail "state directory changed"
    [ "$TMPDIR" = "$test_root/tmp" ] || fail "temporary directory changed"
    [ "$DBUS_SYSTEM_BUS_ADDRESS" = "unix:path=$test_root/no-system-bus" ] || fail "system bus escaped"
    [ "$DBUS_SESSION_BUS_ADDRESS" = "unix:path=$test_root/no-session-bus" ] || fail "session bus escaped"
    [ "$PLATFORMD_TRUSTD_STATE" = "$test_root/state/trustd" ] || fail "trust state escaped"
    [ "$PLATFORMD_TRUSTD_RUNTIME" = "$test_root/runtime/trustd" ] || fail "trust runtime escaped"
    [ "$PLATFORMD_VERIFYD_RUNTIME" = "$test_root/runtime/verifyd" ] || fail "verification runtime escaped"
    [ "$PLATFORMD_TRUST_SOCKET" = "$test_root/no-trustd" ] || fail "trust endpoint escaped"
    [ "$PLATFORMD_VERIFY_SOCKET" = "$test_root/no-verifyd" ] || fail "verification endpoint escaped"
    [ "$PLATFORMD_ASK_PASSWORD_SOCKET" = "$test_root/no-ask-password" ] || fail "password endpoint escaped"
    [ "$PLATFORMD_VERIFY_PAM_CONFDIR" = "$test_root/no-pam" ] || fail "PAM configuration escaped"
    [ "$TSS2_TCTI" = "device:$test_root/no-tpm" ] || fail "TPM backend escaped"
    [ ! -e "$test_root/no-tpm" ] || fail "TPM backend exists"
    if env | grep -Eq '^(RUNTIME_DIRECTORY|STATE_DIRECTORY|CACHE_DIRECTORY|LOGS_DIRECTORY|CONFIGURATION_DIRECTORY|CREDENTIALS_DIRECTORY|ENCRYPTED_CREDENTIALS_DIRECTORY|NOTIFY_SOCKET|WATCHDOG_USEC|WATCHDOG_PID|LISTEN_PID|LISTEN_FDS|LISTEN_FDNAMES|TPM2TOOLS_TCTI|PLATFORMD_TEST_ENV|XDG_SESSION_ID)='; then
        fail "inherited service environment escaped"
    fi
    exit 0
fi

TRUSTD="$1"
TRUSTCTL="$2"
test_scripts=$(dirname "$0")
hostile_dir=$(mktemp -d)
trap 'rm -rf -- "$hostile_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$hostile_dir/runtime" "$hostile_dir/state" "$hostile_dir/credentials"
printf '%s\n' runtime-sentinel > "$hostile_dir/runtime/io.platformd.Trust"
printf '%s\n' state-sentinel > "$hostile_dir/state/sentinel"
runtime_sum=$(cksum < "$hostile_dir/runtime/io.platformd.Trust")
state_sum=$(cksum < "$hostile_dir/state/sentinel")

hostile_environment() {
    env \
        RUNTIME_DIRECTORY="$hostile_dir/runtime" \
        STATE_DIRECTORY="$hostile_dir/state" \
        CACHE_DIRECTORY="$hostile_dir/state" \
        LOGS_DIRECTORY="$hostile_dir/state" \
        CONFIGURATION_DIRECTORY="$hostile_dir/state" \
        CREDENTIALS_DIRECTORY="$hostile_dir/credentials" \
        ENCRYPTED_CREDENTIALS_DIRECTORY="$hostile_dir/credentials" \
        XDG_RUNTIME_DIR="$hostile_dir/runtime" \
        XDG_DATA_HOME="$hostile_dir/state" \
        XDG_CONFIG_HOME="$hostile_dir/state" \
        XDG_CACHE_HOME="$hostile_dir/state" \
        XDG_STATE_HOME="$hostile_dir/state" \
        XDG_SESSION_ID=hostile-session \
        TMPDIR="$hostile_dir/runtime" \
        DBUS_SYSTEM_BUS_ADDRESS="unix:path=$hostile_dir/system-bus" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$hostile_dir/session-bus" \
        PLATFORMD_TRUSTD_RUNTIME="$hostile_dir/runtime" \
        PLATFORMD_TRUSTD_STATE="$hostile_dir/state" \
        PLATFORMD_VERIFYD_RUNTIME="$hostile_dir/runtime" \
        PLATFORMD_TRUST_SOCKET="$hostile_dir/runtime/io.platformd.Trust" \
        PLATFORMD_VERIFY_SOCKET="$hostile_dir/runtime/io.platformd.Verify" \
        PLATFORMD_ASK_PASSWORD_SOCKET="$hostile_dir/runtime/ask-password" \
        PLATFORMD_VERIFY_PAM_CONFDIR="$hostile_dir/pam" \
        TSS2_TCTI="device:$hostile_dir/no-tpm" \
        TPM2TOOLS_TCTI="device:$hostile_dir/no-tpm" \
        NOTIFY_SOCKET="$hostile_dir/notify" \
        WATCHDOG_USEC=1 WATCHDOG_PID="$$" \
        LISTEN_PID="$$" LISTEN_FDS=1 LISTEN_FDNAMES=hostile \
        PLATFORMD_TEST_ENV=1 \
        "$@"
}

hostile_environment sh "$test_scripts/test-env.sh" \
    sh "$0" --test-inner --check-environment
hostile_environment sh "$test_scripts/test-smoke.sh" "$TRUSTD" "$TRUSTCTL"
hostile_environment sh "$test_scripts/test-integration.sh" "$TRUSTD" "$TRUSTCTL"
[ "$(cksum < "$hostile_dir/runtime/io.platformd.Trust")" = "$runtime_sum" ] || fail "inherited runtime changed"
[ "$(cksum < "$hostile_dir/state/sentinel")" = "$state_sum" ] || fail "inherited state changed"
echo "OK: inherited service environment is isolated"
