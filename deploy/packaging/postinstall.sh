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

# /etc/nebula-agent/agent.yml is intentionally NOT created automatically —
# operators copy from the shipped example and edit before first run.
if [ ! -f /etc/nebula-agent/agent.yml ]; then
    cat <<EOF >&2

  nebula-agent: configuration not yet present.
  Copy the example and edit before starting the service:

    sudo cp /etc/nebula-agent/agent.example.yml /etc/nebula-agent/agent.yml
    sudoedit /etc/nebula-agent/agent.yml
    sudo nebula-agent enroll --server <url> --token <token> --data-dir /etc/nebula
    sudo systemctl enable --now nebula-agent.service

EOF
fi

# Reload systemd so the new unit is visible, but never enable/start
# automatically — operators must enroll first.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
