#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != "--test-inner" ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift
for tool in swtpm tpm2_nvdefine tpm2_nvundefine tpm2_changeauth tpm2_shutdown; do
        command -v "$tool" >/dev/null || exit 77
done

test_binary=$1
test_dir=$(mktemp -d /tmp/platformd-tpm.XXXXXX)
test_pid=
cleanup() {
        if [ -n "$test_pid" ]; then
                kill "$test_pid" 2>/dev/null || :
                wait "$test_pid" || :
        fi
        rm -rf -- "$test_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_tpm() {
        test_socket="$test_dir/tpm-$1.sock"
        swtpm socket --tpm2 --tpmstate "dir=$test_dir" \
                --server "type=unixio,path=$test_socket" \
                --ctrl "type=unixio,path=$test_socket.ctrl" \
                --flags not-need-init,startup-clear &
        test_pid=$!
        i=0
        while [ ! -S "$test_socket" ]; do
                i=$((i + 1))
                [ "$i" -lt 100 ]
                sleep 0.01
        done
        export TSS2_TCTI="swtpm:path=$test_socket"
        export TPM2TOOLS_TCTI="$TSS2_TCTI"
}

restart_tpm() {
        tpm2_shutdown -c
        kill "$test_pid"
        wait "$test_pid"
        test_pid=
        start_tpm "$1"
}

start_tpm initial

tpm2_nvdefine 0x01800001 -C o -s 32 -a 'ownerread|ownerwrite'
"$test_binary" conflict
tpm2_nvundefine 0x01800001 -C o
"$test_binary" valid
restart_tpm reset
"$test_binary" reset
tpm2_changeauth -c o fixture-owner-auth
"$test_binary" unauthorized
restart_tpm unauthorized
"$test_binary" unauthorized
