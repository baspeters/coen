#!/bin/sh
# Coen package post-install: create the service account, secure the config
# directory, and refresh systemd. Runs on both fresh installs and upgrades,
# so it must stay idempotent and portable across dpkg, rpm, and apk.
set -e

# Create the coen system group and user if they are absent. Prefer the
# shadow-utils tools (Debian/RHEL); fall back to busybox (Alpine).
if ! getent group coen >/dev/null 2>&1 && ! grep -q "^coen:" /etc/group 2>/dev/null; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system coen
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup -S coen
    fi
fi
if ! getent passwd coen >/dev/null 2>&1 && ! grep -q "^coen:" /etc/passwd 2>/dev/null; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid coen --home-dir /etc/coen --no-create-home \
            --shell /usr/sbin/nologin --comment "Coen tunnel" coen
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -G coen -h /etc/coen -s /sbin/nologin coen
    fi
fi

# The daemons run as coen and read their config and PKI from /etc/coen. Take
# ownership of the tree without loosening the mode of any key the operator has
# already placed there (so a 0600 private key stays 0600).
if [ -d /etc/coen ]; then
    chown -R coen:coen /etc/coen 2>/dev/null || true
    chmod 0750 /etc/coen 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
