# systemd units

## nebula-mgmt.service

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nebula-mgmt
sudo install -m 0755 bin/nebula-mgmt /usr/local/bin/nebula-mgmt

sudo install -d -o nebula-mgmt -g nebula-mgmt -m 0750 \
  /etc/nebula-mgmt /var/lib/nebula-mgmt

# 1. Initialize CA + API key (interactive — prompts for CA passphrase).
sudo -u nebula-mgmt nebula-mgmt init --config /etc/nebula-mgmt/server.yml

# 2. Persist the CA passphrase for systemd.
sudo install -m 0600 -o root -g root /dev/null /etc/nebula-mgmt/passphrase.env
sudo tee /etc/nebula-mgmt/passphrase.env > /dev/null <<'EOF'
NEBULA_MGMT_CA_PASSPHRASE=your-ca-passphrase-here
EOF

# 3. Install and enable the unit.
sudo install -m 0644 deploy/systemd/nebula-mgmt.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-mgmt
sudo systemctl status nebula-mgmt
```

The service reads `NEBULA_MGMT_CA_PASSPHRASE` from `passphrase.env` and unlocks the CA non-interactively.

## nebula-agent.service

```sh
sudo install -m 0755 bin/nebula-agent /usr/local/bin/nebula-agent

# First run: enrolls the host and writes /etc/nebula-agent/agent.yml (mode 0600).
sudo nebula-agent \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN"

# The default data_dir is /etc/nebula; pass --data-dir on the first run to change it.

sudo install -m 0644 deploy/systemd/nebula-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-agent
```
