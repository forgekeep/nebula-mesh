#!/bin/sh
set -e

# Create system user/group if missing. The service unit runs the
# nebula-mgmt binary under this user; the operator is expected to
# pre-stage NEBULA_MGMT_MASTER_KEY / NEBULA_MGMT_CA_PASSPHRASE via a
# systemd drop-in or EnvironmentFile before enabling the unit.
if ! getent group nebula-mgmt >/dev/null 2>&1; then
    groupadd --system nebula-mgmt
fi
if ! getent passwd nebula-mgmt >/dev/null 2>&1; then
    useradd --system --gid nebula-mgmt --home-dir /var/lib/nebula-mgmt \
        --shell /usr/sbin/nologin --comment "nebula-mgmt" nebula-mgmt
fi

# Data + config directories with conservative permissions. The CA and
# SQLite DB live under /var/lib/nebula-mgmt — keep it 0750 so casual
# package upgrades cannot leak them.
install -d -o nebula-mgmt -g nebula-mgmt -m 0750 /var/lib/nebula-mgmt
install -d -o root         -g nebula-mgmt -m 0750 /etc/nebula-mgmt

# /etc/nebula-mgmt/server.yml is intentionally NOT created automatically —
# operators copy from the shipped example, set secrets via env, then
# `nebula-mgmt init` before starting the service.
if [ ! -f /etc/nebula-mgmt/server.yml ]; then
    cat <<EOF >&2

  nebula-mgmt: configuration not yet present.
  Bootstrap steps:

    sudo cp /etc/nebula-mgmt/server.example.yml /etc/nebula-mgmt/server.yml
    sudoedit /etc/nebula-mgmt/server.yml

    # Provide the master key + CA passphrase via a systemd drop-in,
    # NOT in server.yml. Example:
    #   sudo systemctl edit nebula-mgmt.service
    #   [Service]
    #   Environment=NEBULA_MGMT_MASTER_KEY=<base64>
    #   Environment=NEBULA_MGMT_CA_PASSPHRASE=<passphrase>

    # Then run init once and enable:
    sudo -u nebula-mgmt -E nebula-mgmt init --config /etc/nebula-mgmt/server.yml
    sudo systemctl enable --now nebula-mgmt.service

EOF
fi

# Reload systemd but never auto-start.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
