#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

case "$1" in
    purge)
        # dpkg purge only: drop the system user. Keep /var/lib/nebula-mgmt
        # and /etc/nebula-mgmt intact — they contain the CA + DB and must
        # survive a package removal.
        if getent passwd nebula-mgmt >/dev/null 2>&1; then
            userdel nebula-mgmt 2>/dev/null || true
        fi
        if getent group nebula-mgmt >/dev/null 2>&1; then
            groupdel nebula-mgmt 2>/dev/null || true
        fi
        ;;
esac

exit 0
