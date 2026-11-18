#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift
client=$1
fixture=$2
test_dir=$(mktemp -d /tmp/platformd-endorsement-cli.XXXXXX)
trap 'rm -rf -- "$test_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$fixture" --write-fixture "$test_dir"
export PLATFORMD_TRUST_SOCKET="$test_dir/no-authority"

reject() {
        if timeout 10s "$client" "$@" >"$test_dir/output" 2>"$test_dir/error"; then
                printf 'Unexpected endorsement command success\n' >&2
                exit 1
        else
                result=$?
        fi
        [ "$result" -eq 1 ]
        [ ! -s "$test_dir/output" ]
        [ -s "$test_dir/error" ]
        if grep -Eq 'Sanitizer|runtime error:' "$test_dir/error"; then
                exit 1
        fi
}

verify() {
        timeout 10s "$client" verify-endorsement "$test_dir/evidence.json" \
                --trust-anchor="$test_dir/root.pem" --certificate-chain="$test_dir/chain.pem" \
                --revocations="$test_dir/revocations.json" >"$test_dir/output"
}

verify
grep -q '"profile" : "io.platformd.Trust.EndorsementVerification.v1"' "$test_dir/output"
grep -q '"endorsementKeyMatched" : true' "$test_dir/output"
grep -q '"certificateChainVerified" : true' "$test_dir/output"
grep -q '"revocationChecked" : true' "$test_dir/output"

reject verify-endorsement
reject verify-endorsement "$test_dir/evidence.json"
reject verify-endorsement "$test_dir/evidence.json" --trust-anchor="$test_dir/root.pem"
reject verify-endorsement "$test_dir/evidence.json" --revocations="$test_dir/revocations.json"
reject verify-endorsement "$test_dir/evidence.json" --trust-anchor="$test_dir/root.pem" \
        --revocations="$test_dir/revocations.json"

for option in --unknown --trust-anchor= --certificate-chain= --revocations= \
        --state-dir=unused --endorsement-key=unused --lifetime=60 \
        "--trust-anchor=$test_dir/root.pem" "--certificate-chain=$test_dir/chain.pem" \
        "--revocations=$test_dir/revocations.json"; do
        reject verify-endorsement "$test_dir/evidence.json" \
                --trust-anchor="$test_dir/root.pem" --certificate-chain="$test_dir/chain.pem" \
                --revocations="$test_dir/revocations.json" "$option"
done

mkfifo "$test_dir/fifo"
truncate -s 1048577 "$test_dir/oversized"
printf '{}{}\n' >"$test_dir/trailing.json"
printf '{}\000' >"$test_dir/nul.json"
for path in missing fifo oversized trailing.json nul.json; do
        reject verify-endorsement "$test_dir/$path" --trust-anchor="$test_dir/root.pem" \
                --certificate-chain="$test_dir/chain.pem" --revocations="$test_dir/revocations.json"
        reject verify-endorsement "$test_dir/evidence.json" --trust-anchor="$test_dir/$path" \
                --certificate-chain="$test_dir/chain.pem" --revocations="$test_dir/revocations.json"
        reject verify-endorsement "$test_dir/evidence.json" --trust-anchor="$test_dir/root.pem" \
                --certificate-chain="$test_dir/$path" --revocations="$test_dir/revocations.json"
        reject verify-endorsement "$test_dir/evidence.json" --trust-anchor="$test_dir/root.pem" \
                --certificate-chain="$test_dir/chain.pem" --revocations="$test_dir/$path"
done

mkdir -m 700 "$test_dir/rejected-state" "$test_dir/cert-state" "$test_dir/pin-state"
reject enrollment-begin "$test_dir/evidence.json" --state-dir="$test_dir/rejected-state" \
        --trust-anchor="$test_dir/root.pem" --revocations="$test_dir/revocations.json" --lifetime=60
[ -z "$(ls -A "$test_dir/rejected-state")" ]
reject enrollment-begin "$test_dir/evidence.json" --state-dir="$test_dir/rejected-state" \
        --trust-anchor="$test_dir/root.pem" --certificate-chain="$test_dir/chain.pem" \
        --revocations="$test_dir/revocations.json" --lifetime=60 --endorsement-key="$test_dir/ek.hex"
[ -z "$(ls -A "$test_dir/rejected-state")" ]

timeout 10s "$client" enrollment-begin "$test_dir/evidence.json" --state-dir="$test_dir/cert-state" \
        --trust-anchor="$test_dir/root.pem" --certificate-chain="$test_dir/chain.pem" \
        --revocations="$test_dir/revocations.json" --lifetime=60 >"$test_dir/cert-challenge.json"
grep -q '"endorsementVerification"' "$test_dir/cert-challenge.json"
grep -q '"credentialHex"' "$test_dir/cert-challenge.json"
timeout 10s "$client" enrollment-begin "$test_dir/evidence.json" --state-dir="$test_dir/pin-state" \
        --endorsement-key="$test_dir/ek.hex" --lifetime=60 >"$test_dir/pin-challenge.json"
grep -q '"credentialHex"' "$test_dir/pin-challenge.json"
if grep -q '"endorsementVerification"' "$test_dir/pin-challenge.json"; then
        exit 1
fi

printf 'Endorsement command-line checks passed.\n'
