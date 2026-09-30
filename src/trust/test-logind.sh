#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        exec sh "$(dirname "$0")/test-env.sh" dbus-run-session -- sh "$0" --test-inner "$@"
fi
shift
export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
exec "$@"
