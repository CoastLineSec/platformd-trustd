#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift
client=$1
fixture=$2
test_dir=$(mktemp -d /tmp/platformd-attestation-cli.XXXXXX)
trap 'rm -rf -- "$test_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$fixture" --write-fixture "$test_dir"
nonce=$(cat "$test_dir/nonce.hex")
export PLATFORMD_TRUST_SOCKET="$test_dir/no-authority"

reject() {
        if timeout 5s "$client" verify-attestation "$@" >"$test_dir/output" 2>"$test_dir/error"; then
                printf 'Unexpected verification success\n' >&2
                exit 1
        else
                result=$?
        fi
        [ "$result" -eq 1 ]
        [ ! -s "$test_dir/output" ]
}

timeout 5s "$client" verify-attestation "$test_dir/token.json" \
        --attestation-key="$test_dir/ak.hex" --nonce="$nonce" >"$test_dir/output"
grep -q '"retainedEvents"' "$test_dir/output"
grep -q '"quoteSignatureVerified"' "$test_dir/output"

reject
reject "$test_dir/token.json"
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex"
reject "$test_dir/token.json" --nonce="$nonce"
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex" --nonce=00
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex" --nonce="$nonce" --nonce="$nonce"
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex" --nonce="$nonce" --unknown
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex" --nonce="$nonce" extra
reject "$test_dir/token.json" --attestation-key="$test_dir/ak.hex" --nonce=
reject "$test_dir/token.json" --attestation-key= --nonce="$nonce"
reject "$test_dir/missing" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
reject "$test_dir/token.json" --attestation-key="$test_dir/missing" --nonce="$nonce"

mkfifo "$test_dir/fifo"
reject "$test_dir/fifo" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
reject "$test_dir/token.json" --attestation-key="$test_dir/fifo" --nonce="$nonce"
reject "$test_dir" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
truncate -s 16777217 "$test_dir/oversized"
reject "$test_dir/oversized" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
truncate -s 4097 "$test_dir/oversized-key"
reject "$test_dir/token.json" --attestation-key="$test_dir/oversized-key" --nonce="$nonce"
cp "$test_dir/token.json" "$test_dir/nul.json"
printf '\000' >>"$test_dir/nul.json"
reject "$test_dir/nul.json" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
printf '{}{}\n' >"$test_dir/trailing.json"
reject "$test_dir/trailing.json" --attestation-key="$test_dir/ak.hex" --nonce="$nonce"
printf 'not a key\n' >"$test_dir/bad-key"
reject "$test_dir/token.json" --attestation-key="$test_dir/bad-key" --nonce="$nonce"

printf 'Attestation command-line checks passed.\n'
