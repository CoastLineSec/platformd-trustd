#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift
client=$1
fixture=$2
test_dir=$(mktemp -d /tmp/platformd-attestation-appraise-cli.XXXXXX)
trap 'rm -rf -- "$test_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$fixture" --write-fixture "$test_dir"
nonce=$(cat "$test_dir/nonce.hex")
phase=enter-initrd:leave-initrd:sysinit:ready
pcr11=bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da
printf '{"sha256":[{"phase":"%s","pcr":11,"hash":"%s"}]}\n' \
        "$phase" "$pcr11" >"$test_dir/reference.json"
cp "$test_dir/reference.json" "$test_dir/boot-reference.json"
export PLATFORMD_TRUST_SOCKET="$test_dir/no-authority"
export PLATFORMD_TRUSTD_STATE="$test_dir"

accept() {
        timeout 5s "$client" appraise-attestation "$@" >"$test_dir/output" 2>"$test_dir/error"
        [ ! -s "$test_dir/error" ]
        grep -q '"approvedPcr11Matched"[[:space:]]*:[[:space:]]*true' "$test_dir/output"
        grep -q '"quoteSignatureVerified"[[:space:]]*:[[:space:]]*true' "$test_dir/output"
        grep -q '"approvedPhase"' "$test_dir/output"
        if grep -Eq '"(approvedBoot|authenticated|authenticationFresh|policySatisfied)"' "$test_dir/output"; then
                printf 'Unexpected appraisal claim\n' >&2
                exit 1
        fi
}

reject() {
        if timeout 5s "$client" appraise-attestation "$@" >"$test_dir/output" 2>"$test_dir/error"; then
                printf 'Unexpected appraisal success\n' >&2
                exit 1
        else
                result=$?
        fi
        [ "$result" -eq 1 ]
        [ ! -s "$test_dir/output" ]
}

set -- "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" \
       "--reference=$test_dir/reference.json" "--phase=$phase"
accept "$@"
accept "--phase=$phase" "--reference=$test_dir/reference.json" "--nonce=$nonce" \
       "--attestation-key=$test_dir/ak.hex" "$test_dir/token.json"
reject
reject "$test_dir/token.json"
reject "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--nonce=$nonce" "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/reference.json"
reject "$@" "--attestation-key=$test_dir/ak.hex"
reject "$@" "--nonce=$nonce"
reject "$@" "--reference=$test_dir/reference.json"
reject "$@" "--phase=$phase"
reject "$@" --unknown
reject "$@" extra
reject "$test_dir/token.json" --attestation-key= "--nonce=$nonce" "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" --nonce= "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" --reference= "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/reference.json" --phase=
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" --nonce=00 "--reference=$test_dir/reference.json" "--phase=$phase"
reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/reference.json" --phase=enter-initrd

mkfifo "$test_dir/fifo"
truncate -s 16777217 "$test_dir/oversized-token"
truncate -s 4097 "$test_dir/oversized-key"
truncate -s 1048577 "$test_dir/oversized-reference"
for path in "$test_dir/missing" "$test_dir/fifo" "$test_dir" "$test_dir/oversized-token"; do
        reject "$path" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/reference.json" "--phase=$phase"
done
for path in "$test_dir/missing" "$test_dir/fifo" "$test_dir" "$test_dir/oversized-key"; do
        reject "$test_dir/token.json" "--attestation-key=$path" "--nonce=$nonce" "--reference=$test_dir/reference.json" "--phase=$phase"
done
for path in "$test_dir/missing" "$test_dir/fifo" "$test_dir" "$test_dir/oversized-reference"; do
        reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$path" "--phase=$phase"
done

cp "$test_dir/reference.json" "$test_dir/nul-reference"
printf '\000' >>"$test_dir/nul-reference"
printf '{}{}\n' >"$test_dir/trailing-reference"
printf '{"sha256":[]}\n' >"$test_dir/empty-reference"
printf '{"sha256":[],"sha256":[{"phase":"%s","pcr":11,"hash":"%s"}]}\n' \
        "$phase" "$pcr11" >"$test_dir/duplicate-reference"
printf '{"sha256":[{"phase":"%s","pcr":11.0,"hash":"%s"}]}\n' \
        "$phase" "$pcr11" >"$test_dir/real-pcr-reference"
printf '{"sha256":[{"phase":"%s","pcr":11,"hash":"%064d"}]}\n' \
        "$phase" 0 >"$test_dir/unapproved-reference"
for name in nul-reference trailing-reference empty-reference duplicate-reference real-pcr-reference unapproved-reference; do
        reject "$test_dir/token.json" "--attestation-key=$test_dir/ak.hex" "--nonce=$nonce" "--reference=$test_dir/$name" "--phase=$phase"
done

printf 'Attestation appraisal command-line checks passed.\n'
