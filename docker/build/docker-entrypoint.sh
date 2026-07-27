#!/bin/sh
# OpenTARS — container entrypoint.
#
# The app runs as the unprivileged "threatbox" user (uid/gid 10001), but the
# Compose file bind-mounts host directories (./threatbox-data, ./threatbox-logs)
# which Docker creates root-owned. This entrypoint runs briefly as root only to
# fix the ownership of those mount points, then drops privileges via gosu and
# hands off to the app's own startup script ("$@"). The application process
# itself always runs unprivileged.
set -e

APP_HOME=/home/threatbox

if [ "$(id -u)" = "0" ]; then
    for dir in "${APP_HOME}/data" "${APP_HOME}/logs"; do
        mkdir -p "${dir}"
        chown threatbox:threatbox "${dir}" 2>/dev/null || true
    done
    exec gosu threatbox "$@"
fi

exec "$@"
