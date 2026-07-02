#!/bin/sh
# Coen package pre-remove: on a real uninstall (not an upgrade) stop and
# disable the services. dpkg passes "remove"/"purge" as $1; rpm passes "0".
# Alpine uses OpenRC rather than systemd, so the systemctl guard makes this a
# no-op there.
set -e

case "$1" in
    remove | purge | 0)
        if command -v systemctl >/dev/null 2>&1; then
            for svc in coen-edge coen-agent; do
                systemctl disable --now "$svc" >/dev/null 2>&1 || true
            done
        fi
        ;;
esac

exit 0
