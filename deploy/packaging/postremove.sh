#!/bin/sh
set -e

# Reload systemd after unit file disappearance. Keep /etc/nebula-agent and
# /etc/nebula intact so host keys, certs, and operator edits survive a
# package removal — operators clean these up manually if desired.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

case "$1" in
    purge)
        # dpkg purge only: also remove the system user.
        if getent passwd nebula-agent >/dev/null 2>&1; then
            userdel nebula-agent 2>/dev/null || true
        fi
        if getent group nebula-agent >/dev/null 2>&1; then
            groupdel nebula-agent 2>/dev/null || true
        fi
        ;;
esac

exit 0
