#!/bin/sh
set -e

case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop nebula-mgmt.service 2>/dev/null || true
            systemctl disable nebula-mgmt.service 2>/dev/null || true
        fi
        ;;
esac

exit 0
