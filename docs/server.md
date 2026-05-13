# nebula-mgmt

The `nebula-mgmt` server is the control plane for the mesh. It issues
host certificates, manages networks and operators, distributes config to
agents via `/api/v1/agent/updates`, and exposes the Web UI + REST API +
CLI from a single Go binary.

This document covers production usage — installation, configuration,
day-2 operations, upgrade. The 30-second walkthrough lives in the
project [README](../README.md).

## Runtime requirements

- A Linux host (Debian / Ubuntu / RHEL family supported by the
  packages below; tarball fallback for the rest).
- Persistent storage for `data_dir` (default `/var/lib/nebula-mgmt`) —
  the SQLite database, the encrypted CA material, and the operator
  data all live here.
- The `NEBULA_MGMT_MASTER_KEY` (base64 32-byte AES-256 key) **must** be
  supplied at startup via an environment variable. The key is never
  written to disk by the server; loss of the key means loss of the
  ability to mint new certificates against existing CAs.
- ~25 MiB of disk for the binary; runtime memory typically < 100 MiB.

## Installation

### Linux distro packages (recommended)

Each tagged release publishes `.deb` and `.rpm` packages for `amd64` and
`arm64` alongside the agent package:

```sh
TAG=$(curl -fsSL https://api.github.com/repos/juev/nebula-mesh/releases/latest | grep -m1 tag_name | cut -d'"' -f4)
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Debian / Ubuntu
curl -fsSL -O "https://github.com/juev/nebula-mesh/releases/download/${TAG}/nebula-mgmt_${TAG#v}_linux_${ARCH}.deb"
sudo apt install -y "./nebula-mgmt_${TAG#v}_linux_${ARCH}.deb"

# RHEL / Rocky / Alma / Fedora
sudo rpm -i "https://github.com/juev/nebula-mesh/releases/download/${TAG}/nebula-mgmt_${TAG#v}_linux_${ARCH}.rpm"
```

The package installs:

- `/usr/bin/nebula-mgmt` — the server binary;
- `/lib/systemd/system/nebula-mgmt.service` — the systemd unit;
- `/etc/nebula-mgmt/server.example.yml` — example config (marked
  `config|noreplace` so upgrades preserve your edits);
- `/var/lib/nebula-mgmt/` — empty data dir, mode `0750`, owned by the
  newly-created `nebula-mgmt` system user;
- `/usr/share/doc/nebula-mgmt/{README,LICENSE,CHANGELOG,server.md}` —
  docs;
- `/usr/share/doc/nebula-mgmt/reverse-proxy/{nginx.conf,Caddyfile,traefik-dynamic.yml}` —
  reverse-proxy snippets you can `cp` into the right system directory.

The post-install script **does not** start or enable the unit; you
must complete bootstrap first (see *Bootstrap* below).

### Tarball / Docker

For platforms without a native package (macOS dev install, FreeBSD,
non-standard Linux distros) or container deployments, fall back to the
prebuilt tarball or the published Docker image — see the
[Install](../README.md#install) section in the README.

## Bootstrap

```sh
# 1. Drop the secrets into a systemd drop-in so they never appear in
#    /etc/nebula-mgmt/server.yml and never enter your VCS.
sudo systemctl edit nebula-mgmt.service
# [Service]
# Environment=NEBULA_MGMT_MASTER_KEY=<base64-32-byte-key>
# Environment=NEBULA_MGMT_CA_PASSPHRASE=<long-random-passphrase>

# 2. Materialise the config from the shipped example and edit.
sudo cp /etc/nebula-mgmt/server.example.yml /etc/nebula-mgmt/server.yml
sudoedit /etc/nebula-mgmt/server.yml

# 3. Run init exactly once. The script creates the initial admin
#    operator and seeds the first CA.
sudo -u nebula-mgmt -E nebula-mgmt init --config /etc/nebula-mgmt/server.yml

# 4. Enable + start.
sudo systemctl enable --now nebula-mgmt.service
sudo journalctl -u nebula-mgmt -f
```

The post-install reminder printed by the package walks operators
through these same steps.

## Reverse proxy

The server speaks plain HTTP on the bind address by default. Always
front it with a TLS-terminating proxy unless your network is
unconditionally trusted.

Three working snippets ship in the package at
`/usr/share/doc/nebula-mgmt/reverse-proxy/` (and in the repo under
[`deploy/reverse-proxy/`](../deploy/reverse-proxy/)):

- `nginx.conf` — nginx ≥ 1.18 + certbot.
- `Caddyfile`  — Caddy 2.x with automatic Let's Encrypt.
- `traefik-dynamic.yml` — Traefik v3 file provider.

All three preserve `X-Forwarded-For` so the management server's per-IP
rate limiter (issue #52) keys on the real client IP — set
`rate_limit.trust_proxy_header: true` in `server.yml` to opt into that.

## Upgrade

```sh
sudo apt install -y "./nebula-mgmt_<new-version>_linux_<arch>.deb"
# rpm equivalent:
# sudo rpm -U "./nebula-mgmt_<new-version>_linux_<arch>.rpm"
```

The deb / rpm post-install runs `systemctl daemon-reload`; if the unit
was already enabled, systemd auto-restarts the service. `/etc/nebula-mgmt/server.yml`
and the data dir survive across upgrades.

When upgrading across a minor version, check the
[CHANGELOG](../CHANGELOG.md) for migration notes — every database
migration is tracked in `internal/store/migrations/`, applied
automatically on startup, and recorded in `schema_migrations`.

## Removal

```sh
sudo apt remove nebula-mgmt      # stops + disables the service, keeps data
sudo apt purge  nebula-mgmt      # additionally drops the system user
```

`apt purge` **never** deletes `/var/lib/nebula-mgmt` (CA + DB) or
`/etc/nebula-mgmt/`. Clean them up manually if you really mean to
nuke the install:

```sh
sudo rm -rf /var/lib/nebula-mgmt /etc/nebula-mgmt
```

The rpm equivalents are `rpm -e nebula-mgmt` and the same manual
clean-up afterwards.

## Backups

The whole server state collapses to a single SQLite file. With the
service running:

```sh
sudo -u nebula-mgmt sqlite3 /var/lib/nebula-mgmt/nebula.db \
  ".backup /backups/nebula-$(date +%F).db"
```

The `NEBULA_MGMT_MASTER_KEY` is **load-bearing**: the DB on its own
is useless without the matching key. Keep both in your secret manager.

## Troubleshooting

### `database is locked` errors at startup

Most often a leftover `*-wal` / `*-shm` file from a hard crash. Stop
the service, run `sqlite3 /var/lib/nebula-mgmt/nebula.db "PRAGMA
wal_checkpoint(TRUNCATE);"`, then start again.

### Bootstrap admin password not shown

`nebula-mgmt init` prints the seeded admin's username and one-time
password to stdout. The package log capture in `journalctl` shows it
only on the first start of the service. If you missed it, run:

```sh
sudo -u nebula-mgmt -E nebula-mgmt user create --username admin --role admin
```

to mint a new admin operator (the existing seed user keeps its TOTP
binding, if any).

### `permission denied` on `/var/lib/nebula-mgmt`

The package sets `0750 nebula-mgmt:nebula-mgmt` on the data dir. If a
previous install left it as root-owned, fix it:

```sh
sudo chown -R nebula-mgmt:nebula-mgmt /var/lib/nebula-mgmt
sudo chmod 0750                       /var/lib/nebula-mgmt
```
