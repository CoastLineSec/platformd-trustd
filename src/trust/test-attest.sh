#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != "--test-inner" ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift
for tool in swtpm tpm2_nvdefine tpm2_nvundefine tpm2_changeauth; do
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

swtpm socket --tpm2 --tpmstate "dir=$test_dir" \
        --server "type=unixio,path=$test_dir/tpm.sock" \
        --ctrl "type=unixio,path=$test_dir/tpm.sock.ctrl" \
        --flags not-need-init,startup-clear &
test_pid=$!
i=0
while [ ! -S "$test_dir/tpm.sock" ]; do
        i=$((i + 1))
        [ "$i" -lt 100 ]
        sleep 0.01
done
export TSS2_TCTI="swtpm:path=$test_dir/tpm.sock"
export TPM2TOOLS_TCTI="$TSS2_TCTI"

tpm2_nvdefine 0x01800001 -C o -s 32 -a 'ownerread|ownerwrite'
"$test_binary" conflict
tpm2_nvundefine 0x01800001 -C o
"$test_binary" valid
tpm2_changeauth -c o fixture-owner-auth
"$test_binary" unauthorized
