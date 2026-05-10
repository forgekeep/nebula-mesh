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
sudo install -d -m 0755 /etc/nebula-agent
sudo install -m 0644 configs/agent.example.yml /etc/nebula-agent/agent.yml

# Edit /etc/nebula-agent/agent.yml: set server_url, data_dir, nebula_pid_file.
# Then enroll once (writes host.crt/key and config.yml to data_dir):
sudo nebula-agent enroll --server https://mgmt.example.com:8080 \
                        --token "$ENROLL_TOKEN" --data-dir /etc/nebula

sudo install -m 0644 deploy/systemd/nebula-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-agent
```
