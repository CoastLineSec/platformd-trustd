#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

hook=$(realpath "${1:?}")
trustctl=$(realpath "${2:?}")
mkdir "$TMPDIR/bin" "$TMPDIR/staging" "$PLATFORMD_TRUSTD_STATE"
ln -s "$trustctl" "$TMPDIR/bin/trustctl"
PATH="$TMPDIR/bin:$PATH"
export PATH
export KERNEL_INSTALL_STAGING_AREA="$TMPDIR/staging"
export KERNEL_INSTALL_LAYOUT=uki

if sh "$hook" add missing /nonexistent; then
    exit 1
fi

mkdir "$PLATFORMD_TRUSTD_STATE/boot-references"
touch "$PLATFORMD_TRUSTD_STATE/boot-references/stale.json" "$TMPDIR/staging/uki.efi"
if sh "$hook" add stale /nonexistent; then
    exit 1
fi
[ ! -e "$PLATFORMD_TRUSTD_STATE/boot-references/stale.json" ]

touch "$PLATFORMD_TRUSTD_STATE/boot-references/remove.json"
KERNEL_INSTALL_LAYOUT=other sh "$hook" remove remove /nonexistent
[ ! -e "$PLATFORMD_TRUSTD_STATE/boot-references/remove.json" ]
KERNEL_INSTALL_LAYOUT=other sh "$hook" add ignored /nonexistent
sh "$hook" inspect ignored /nonexistent
