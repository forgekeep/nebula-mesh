#!/bin/sh
set -e

# Create system user/group if missing. Used to give the operator a clear
# target for hardening, even though the shipped systemd unit still runs as
# root because the agent needs to write into /etc/nebula and SIGHUP nebula.
if ! getent group nebula-agent >/dev/null 2>&1; then
    groupadd --system nebula-agent
fi
if ! getent passwd nebula-agent >/dev/null 2>&1; then
    useradd --system --gid nebula-agent --home-dir /var/lib/nebula-agent \
        --shell /usr/sbin/nologin --comment "nebula-agent" nebula-agent
fi

# /etc/nebula-agent/agent.yml is created by `nebula-agent enroll` (#88) and
# is intentionally NOT created here. The daemon happily sits in idle-standby
# without it; the operator binds the host with one command.
if [ ! -f /etc/nebula-agent/agent.yml ]; then
    cat <<'EOF' >&2

  nebula-agent: not yet enrolled — service will start in idle-standby.
  Bind the host with one command:

    sudo nebula-agent enroll --server <url> --token <token>

  The running daemon will pick up the fresh enrollment within ~10s
  without a restart.

EOF
fi

# Reload systemd so the new unit is visible. On a fresh install (DEB:
# $1=configure with no $2; RPM: $1=1) enable and start the service so the
# daemon is up immediately — it sits idle until the operator enrolls,
# which is now a safe default thanks to #88. On upgrade ($1=2 for RPM,
# $1=configure with $2 set for DEB) leave the current enable-state alone.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    fresh_install=0
    case "${1:-}" in
        "")           fresh_install=1 ;;
        configure)    if [ -z "${2:-}" ]; then fresh_install=1; fi ;;
        1)            fresh_install=1 ;;
    esac
    if [ "${fresh_install}" = "1" ]; then
        systemctl enable --now nebula-agent.service >/dev/null 2>&1 || true
    fi
fi

exit 0
