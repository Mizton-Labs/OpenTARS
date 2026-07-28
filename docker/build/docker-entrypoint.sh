#!/bin/sh
# OpenTARS — container entrypoint.
#
# The app runs as the unprivileged "opentars" user (uid/gid 10001), but the
# Compose file bind-mounts host directories (./opentars-data, ./opentars-logs)
# which Docker creates root-owned. This entrypoint runs briefly as root only to
# fix the ownership of those mount points, then drops privileges via gosu and
# hands off to the app's own startup script ("$@"). The application process
# itself always runs unprivileged.
set -e

APP_HOME=/home/opentars

if [ "$(id -u)" = "0" ]; then
    for dir in "${APP_HOME}/data" "${APP_HOME}/logs"; do
        mkdir -p "${dir}"
        chown opentars:opentars "${dir}" 2>/dev/null || true
    done
    exec gosu opentars "$@"
fi

exec "$@"
