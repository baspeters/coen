#!/bin/sh
# Coen package post-remove: refresh systemd once the unit files are gone. The
# coen user and /etc/coen are left in place so an operator's config and keys
# survive an uninstall.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
