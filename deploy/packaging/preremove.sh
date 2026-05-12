#!/bin/sh
set -e

# Stop and disable the service if it is running, but only on full removal —
# not on upgrade. Both dpkg and rpm pass an argument distinguishing these.
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop nebula-agent.service 2>/dev/null || true
            systemctl disable nebula-agent.service 2>/dev/null || true
        fi
        ;;
esac

exit 0
