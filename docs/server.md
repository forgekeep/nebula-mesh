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
  the SQLite database and all CA material encrypted at rest live here.
- The `NEBULA_MGMT_MASTER_KEY` (base64 32-byte AES-256 key) **must** be
  supplied at startup via:
  - Environment variable `NEBULA_MGMT_MASTER_KEY` (recommended for systemd / Docker), or
  - The `master_key` field in `server.yml` (base64-encoded).
  The key is never written to disk by the server; loss of the key means loss of the
  ability to mint new certificates against existing CAs.
- ~25 MiB of disk for the binary; runtime memory typically < 100 MiB.

## Installation

### Linux distro packages (recommended)

Each tagged release publishes `.deb` and `.rpm` packages for `amd64` and
`arm64` alongside the agent package:

```sh
TAG=$(curl -fsSL https://api.github.com/repos/forgekeep/nebula-mesh/releases/latest | grep -m1 tag_name | cut -d'"' -f4)
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Debian / Ubuntu
curl -fsSL -O "https://github.com/forgekeep/nebula-mesh/releases/download/${TAG}/nebula-mgmt_${TAG#v}_linux_${ARCH}.deb"
sudo apt install -y "./nebula-mgmt_${TAG#v}_linux_${ARCH}.deb"

# RHEL / Rocky / Alma / Fedora
sudo rpm -i "https://github.com/forgekeep/nebula-mesh/releases/download/${TAG}/nebula-mgmt_${TAG#v}_linux_${ARCH}.rpm"
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
# 1. Generate a master key (required for CA encryption) and set it in a
#    systemd drop-in so it never appears in /etc/nebula-mgmt/server.yml.
openssl rand -base64 32
sudo systemctl edit nebula-mgmt.service
# [Service]
# Environment=NEBULA_MGMT_MASTER_KEY=<base64-32-byte-key>

# 2. Materialise the config from the shipped example and edit.
sudo cp /etc/nebula-mgmt/server.example.yml /etc/nebula-mgmt/server.yml
sudoedit /etc/nebula-mgmt/server.yml

# 3. Run init exactly once. The script creates the initial admin
#    operator and provisions the admin-default CA.
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
rate limiter (issue #52) keys on the real client IP. Set
`rate_limit.trust_proxy_header: true` in `server.yml` to opt into that.
The bundled proxies connect from loopback, which is trusted automatically.
If a container or cluster proxy connects from another address, list only
the proxy network:

```yaml
rate_limit:
  trust_proxy_header: true
  trusted_proxies:
    - "10.42.0.0/16"
```

Do not add client networks to `trusted_proxies`. An untrusted direct peer
cannot select the rate-limit key through `X-Forwarded-For`.

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
is useless without the matching key. Keep the master key in your secret
manager — it is not stored in the database or configuration.

## Networks and Hosts

### Creating a network

Networks can contain one or more CIDR prefixes, enabling dual-stack (IPv4 + IPv6)
and segmented address schemes. Create via the Web UI or REST API:

```bash
curl -X POST "https://mgmt.example.com:8080/api/v1/networks" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production",
    "cidrs": ["10.42.0.0/24", "fd00:42::/64"]
  }'
```

Response (201):
```json
{
  "id": "net_abc123",
  "name": "production",
  "cidrs": ["10.42.0.0/24", "fd00:42::/64"],
  "ca_id": "ca_xyz789",
  "created_at": "2026-05-14T10:30:00Z"
}
```

### Creating a host

Hosts are assigned one or more overlay addresses from the parent network's CIDR
prefixes. When multiple addresses are provided, the host's certificate includes
all of them; the configuration generated for the host references all addresses
in `static_host_map` and `lighthouse.hosts`.

```bash
curl -X POST "https://mgmt.example.com:8080/api/v1/hosts" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "network_id": "net_abc123",
    "name": "edge-1",
    "nebula_ips": ["10.42.0.10", "fd00:42::10"],
    "role": "host"
  }'
```

Response (201):
```json
{
  "id": "host_def456",
  "network_id": "net_abc123",
  "name": "edge-1",
  "nebula_ips": ["10.42.0.10", "fd00:42::10"],
  "role": "host",
  "status": "pending",
  "groups": [],
  "created_at": "2026-05-14T10:31:00Z"
}
```

**Field notes:**

- `cidrs` (networks): array of CIDR strings. Each CIDR must be unique and non-overlapping within the network. At least one is required.
- `nebula_ips` (hosts): array of IP address strings. Each address must fall within one of the parent network's CIDRs. At least one is required. Order is preserved in the issued certificate.
- Legacy singular fields (`cidr` and `nebula_ip`) were removed in v0.3.0. Requests using the old field names receive a 400 Bad Request error.

### Updating certificate-bound fields

`name`, `nebula_ips` and `groups` are all carried inside the host's Nebula
certificate, so editing any of them schedules a re-issuance: the host row is
flagged `pending_rekey`, the next poll answers `rekey_required: true` with a
single-use enrollment token, and the agent re-enrolls with a certificate that
reflects the change. Other fields (`role`, `public_ip`, `listen_port`,
`advanced`) only affect the rendered config and are picked up on the next poll
without a new certificate.

This matters most for `groups`. Peers authorize each other on the certificate,
and firewall rules select their counterparties by group, so a group edit does
nothing on the mesh until the new certificate lands. Note that the previous
certificate stays valid until it expires — removing a host from a group closes
its new sessions' access once the host re-enrolls, but it does not retroactively
invalidate the old certificate. Block the host (which adds its fingerprint to
the blocklist) when you need immediate, enforced revocation.

To change a host's addresses, use PATCH:

```bash
curl -X PATCH "https://mgmt.example.com:8080/api/v1/hosts/host_def456" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "nebula_ips": ["fd00:42::10", "10.42.0.10"]
  }'
```

The new certificate will reflect the reordered addresses on the agent's next poll.

Changing group membership works the same way:

```bash
curl -X PATCH "https://mgmt.example.com:8080/api/v1/hosts/host_def456" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "groups": ["web", "prod"]
  }'
```

## Hosts

### Mobile hosts (iOS / Android)

The [Mobile Nebula](https://apps.apple.com/app/mobile-nebula/id1509587936)
app (iOS) and
[Mobile Nebula](https://play.google.com/store/apps/details?id=net.defined.mobile_nebula)
app (Android) allow iOS and Android devices to join a Nebula mesh. Unlike
regular hosts that run the `nebula-agent` daemon, mobile devices import a
self-contained Nebula configuration file (in YAML format) bundled with
inline certificates and keys.

#### Creating a mobile host

1. In the Web UI, navigate to **Hosts** → **New Host**.
2. Select **Kind: Mobile** and choose the device type (**Variant: iOS** or
   **Variant: Android**). The host's role is automatically set to `host`
   (mobile devices cannot be lighthouses or relays).
3. Fill in the remaining fields (Name, IP address, Groups) as you would for a
   standard host.
4. Submit. The mobile host is created but is **not yet enrolled** — no
   enrollment token is issued.

#### Generating the mobile bundle

1. Navigate to the mobile host's detail page.
2. Click **Generate Mobile Bundle**. The server will:
   - Generate a fresh X25519 keypair
   - Mint a certificate signed by your CA
   - Create a self-contained Nebula YAML configuration with inline PEM blocks
     for `pki.ca`, `pki.cert`, and `pki.key`
3. The result page displays:
   - The YAML configuration as a code block
   - A QR code encoding the same YAML (for quick import into Mobile Nebula)
   - A download link for the YAML file
4. **Save the YAML immediately.** The private key is shown only once; it is
   **not stored on the server**. Once you close the page, you cannot recover
   the key.

#### Importing the bundle into Mobile Nebula

1. On your iOS or Android device, install **Mobile Nebula** from the App Store
   or Play Store.
2. Open the app and create a new profile.
3. Import the configuration file via one of:
   - Scan the QR code shown in the Web UI
   - Copy-paste the YAML configuration
   - Download the YAML file and share it to the Mobile Nebula app

#### Rotating the certificate

To rotate a mobile host's certificate (when approaching expiry or after a
security incident):

1. On the mobile host's detail page, click **Regenerate Bundle (Rotate Cert)**.
   This generates a new keypair and certificate.
2. Follow the steps under *Generating the mobile bundle* to download and import
   the new configuration into Mobile Nebula.

Each regeneration creates a fresh certificate. The old certificate remains
valid for a short overlap window (to avoid disrupting active connections) and
is automatically revoked after 30 days.

#### Certificate lifetime

Mobile certificates have a **365-day default lifetime**, compared to 30 days for
agent-managed hosts. This longer lifetime reduces the operational burden of
manual bundle regeneration and import on mobile devices.

However, the certificate lifetime is **clamped to the remaining validity of your
CA**. If your CA certificate is close to expiry, the generated mobile
certificate will expire sooner. For example, if your CA expires in 180 days, a
mobile certificate issued today will expire in 180 days (not 365).

**Operational implication:** Before your CA certificate expires, rotate it and
regenerate all mobile bundles. Failing to do so will leave mobile devices with
expired certificates, unable to connect to the mesh.

#### Revocation

To revoke (block) a mobile host:

1. On the mobile host's detail page, click **Block**. The host's certificate
   fingerprint is added to the blocklist.
2. Other mesh nodes will receive the updated blocklist via their regular poll
   interval and **refuse handshakes** with the blocked fingerprint.

Mobile devices themselves do not poll the management server, so they will not
receive the revocation notice. However, the host is effectively isolated because
peer nodes reject incoming and outgoing connections. To fully remove the device
from the mesh, delete the configuration from the Mobile Nebula app.

#### Updating after network changes

Mobile bundles encode the network's current configuration (lighthouse IP
addresses, port mappings, etc.). If you change your network topology (for
example, promoting a new lighthouse or changing its public IP), previously-generated
bundles become stale.

**To update mobile devices after a network change:**

1. Regenerate the bundle (click **Regenerate Bundle** on the host's detail page).
2. Re-import the new YAML into Mobile Nebula.

There is no automatic update mechanism for mobile clients; manual re-import is
required each time the underlying network configuration changes.

## Adopting an existing mesh

Import the current Nebula CA through `/ui/cas/import` or `nebula-mgmt ca
import`, then create an empty Network bound to that CA. Keep a database backup
and the original host configurations before starting. The server rejects an
import target with existing hosts, another Network using the CA, an existing CA
blocklist, a retired CA, or a CA successor.

Create the collection session at `/ui/mesh-imports/new`. Set
`expected_hosts` when the inventory is known and distribute the displayed
`nmi_` token only to those hosts. The token is reusable only for that session;
it is stored as a hash and stops working at expiry, rotation, cancel, expected
count, or finalize. Registered agents immediately switch to signed Ed25519
polls and do not need another token.

The server keeps at most two outstanding proof challenges per host certificate.
The session limit is twice `expected_hosts`, bounded to 2–4096, or 4096 when the
count is unknown. A host that receives `429 Too Many Requests` should wait for
the `Retry-After` interval and run enrollment again. For fleets that may exceed
4096 simultaneous attempts, start agents in waves; successful registrations
free capacity. Token rotation discards every outstanding challenge from the old
token.

During collection the target Network and CA are frozen against ordinary host,
firewall, rotation and attachment mutations. Hosts remain `importing`; the
server does not send configuration, renew certificates or change their Nebula
files. Review the session preview, resolve every blocker, acknowledge the exact
current warnings, inspect each proposed Host status and confirm the inventory.
Finalize compares the displayed revision and commits the complete Host set,
firewall, blocklist and next Network config version in one transaction. A Host
whose certificate fingerprint appears in the imported blocklist becomes
`blocked`; every other Host becomes `enrolled`. The blocked agent receives
`403 revoked` on its next signed poll.

Unblocking an imported Host authorizes its existing identity. The server
accepts the old agent signing key immediately, removes the old certificate
fingerprint from the blocklist and bumps the config version of every Network
using that CA. Peers accept the old Nebula certificate after their next config
poll and apply. Use a separate re-enrollment or force-rotate operation to issue
new credentials; unblock does not replace them.

Cancel a failed collection instead of editing its temporary rows. Cancellation
removes the staged hosts without touching remote files; create a new session
for another attempt. After finalize, recover connectivity from each agent's
one-time config backup and restore a pre-finalize control-plane backup if the
committed topology itself must be reverted. The full host procedure and
compatibility matrix are in [docs/agent.md](agent.md#import-an-existing-mesh);
database recovery is in [docs/backup.md](backup.md#mesh-import-recovery).

## CA Rotation

### Overview

When a CA approaches its expiry date (≤20% lifetime remaining), the Web UI displays
a warning badge alerting the operator. The operator can manually rotate the CA via
the UI, REST API, or CLI; a new CA is created as the successor of the old one.
Existing host certificates signed by the old CA remain valid until their natural
expiry.

Optionally, an opt-in background worker can automatically rotate approaching-expiry CAs.

### Manual rotation

**Web UI:** Navigate to **/ui/cas** or the CA detail page; click the **Rotate** button.

**REST API:**
```bash
curl -X POST "https://mgmt.example.com:8080/api/v1/cas/<ca-id>/rotate" \
  -H "Authorization: Bearer $API_KEY"
```

Response (201):
```json
{
  "id": "ca_new123",
  "name": "tenant-a",
  "predecessor_id": "ca_old789",
  "status": "active",
  "created_at": "2026-05-15T12:00:00Z"
}
```

**CLI:**
```bash
nebula-mgmt ca rotate --server https://mgmt.example.com:8080 --api-key "$API_KEY" \
  --id ca_xyz789
```

### Storage model

After rotation, the database contains two active CAs:

- **Old CA** (`predecessor_id = NULL`): Remains `status = active`. Any host
  certificates signed by this CA before rotation continue to verify and function
  until their natural expiry.
- **New CA** (`predecessor_id = old-ca-id`): The successor. Same owner, same
  lifetime duration as the old CA, new key material.

When an agent polls `/api/v1/agent/updates`, it receives a **trust bundle** —
the concatenated PEM certificates of both the old and new CA. The agent writes
the trust bundle to disk atomically; Nebula natively parses multi-cert PEM files,
so certificate verification works seamlessly during the transition.

### Opt-in auto-rotation

To enable automatic CA rotation, add the `ca_auto_rotate` section to `server.yml`:

```yaml
ca_auto_rotate:
  enabled: true            # default: false
  interval: 6h             # default: 6h — how often to check for expiring CAs
  threshold: 0.20          # default: 0.20 — rotate when ≤20% lifetime remaining
```

The background scanner:

1. Runs once per `interval` in a separate goroutine.
2. Queries for active CAs with ≤`threshold` lifetime remaining.
3. For each CA, creates a successor via `pki.RotateAndStoreCA`.
4. Records an audit entry `ca.auto_rotated` with the new CA ID.
5. Logs the rotation event.

If an error occurs (e.g., transient database failure), the scanner logs and skips
to the next check interval without blocking server shutdown.

**Default behavior:** Auto-rotation is disabled (`enabled: false`). Operators
retain explicit control over when CAs are rotated.

### Related

- [ADR 0008](../docs/adr/0008-ca-rotation.md) — Hybrid CA rotation design.
- [ADR 0007](../docs/adr/0007-remove-legacy-ca-stack.md) — Per-operator CA storage
  (successor to this feature).

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
