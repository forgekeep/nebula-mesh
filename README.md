# nebula-mesh

[![CI](https://github.com/juev/nebula-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/juev/nebula-mesh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/juev/nebula-mesh?display_name=tag&sort=semver)](https://github.com/juev/nebula-mesh/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/juev/nebula-mesh.svg)](https://pkg.go.dev/github.com/juev/nebula-mesh)
[![Go Report Card](https://goreportcard.com/badge/github.com/juev/nebula-mesh)](https://goreportcard.com/report/github.com/juev/nebula-mesh)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/juev/nebula-mesh)](go.mod)

> Self-hosted control plane for [Slack's Nebula](https://github.com/slackhq/nebula) mesh VPN — issue certificates, manage hosts (including iOS / Android via QR), distribute config, rotate CAs, and roll out changes from one place.

![Dashboard](docs/screenshots/dashboard.png)

<sub>
<strong>UI</strong>:
<a href="docs/screenshots/hosts.png">hosts</a> ·
<a href="docs/screenshots/host-detail.png">host detail</a> ·
<a href="docs/screenshots/host-new-advanced.png">host create (advanced)</a> ·
<a href="docs/screenshots/networks.png">networks</a> ·
<a href="docs/screenshots/profile.png">profile</a><br>
<strong>Auth</strong>:
<a href="docs/screenshots/login.png">login</a> ·
<a href="docs/screenshots/register.png">register</a> ·
<a href="docs/screenshots/2fa-setup.png">2FA setup</a> ·
<a href="docs/screenshots/2fa-enabled.png">2FA enabled + recovery codes</a> ·
<a href="docs/screenshots/login-totp.png">login → TOTP prompt</a>
</sub>

---

Nebula gives you a fast, mTLS-authenticated overlay network. But on its own, it leaves the operator to hand-roll certificate issuance, rotation, distribution and revocation — usually with shell scripts and a CA on a laptop. **nebula-mesh** is the missing management layer: a single Go binary plus an enrollment agent that turn Nebula into a self-service mesh you can run on one VM.

### Install in 30 seconds

On a fresh Debian / Ubuntu VM (`amd64`):

```sh
# 1. Install the server.
VERSION=0.3.2
curl -fsSLO "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/nebula-mgmt_${VERSION}_linux_amd64.deb"
sudo apt install -y "./nebula-mgmt_${VERSION}_linux_amd64.deb"

# 2. Set the master key (required for CA encryption) and initialise.
export NEBULA_MGMT_MASTER_KEY=$(openssl rand -base64 32)
sudo -E nebula-mgmt init --config /etc/nebula-mgmt/server.yml
sudo systemctl enable --now nebula-mgmt
```

Open `http://<server>:8080/ui/` and log in with the password printed by `init`.

For RPM / macOS / FreeBSD / Windows / Docker / source — and the host-side agent — see [Install](#install) below. For host enrolment and CLI walk-through, see [Quickstart](#quickstart).

**Jump to:** [Why](#why) · [Features](#features) · [Architecture](#architecture) · [Install](#install) · [Quickstart](#quickstart) · [Operators & auth](#operators-auth-and-tenancy) · [Deployment](#deployment) · [Endpoints](#endpoints) · [Status](#status) · [Security](#security)

<a name="why"></a>
## Why

When this beats hand-rolled scripts or a managed service:

| | Hand-rolled scripts | DefinedNetworking (managed) | **nebula-mesh** |
|---|---|---|---|
| Self-hosted | ✅ | ❌ | ✅ |
| Web UI + REST API | ❌ | ✅ | ✅ |
| Cert rotation & revocation | manual | ✅ | ✅ |
| Single static binary | ✅ | n/a | ✅ |
| Cost | your time | per-host | free (MIT) |
| Lock-in | none | vendor | none |

<details>
<summary><strong>Features</strong> — what nebula-mesh actually does</summary>
<a name="features"></a>


- **Web UI + REST API + CLI** — one server, three interfaces. Built with chi + Go templates + htmx (no SPA build step). Inline field-level form validation with state preservation on error.
- **PKI lifecycle** — per-operator CAs encrypted at rest in SQLite under a process-wide AES-256-GCM master key (envelope encryption per [ADR 0002](docs/adr/0002-per-operator-cas.md)); per-host certs signed via `slackhq/nebula/cert`; blocklist-backed revocation. New operators get a default CA auto-provisioned on first sign-in.
- **CA rotation** — when a CA approaches expiry (≤20% lifetime left), a warning badge appears in the UI; operators rotate manually with one click or opt into background auto-rotation. Existing host certificates remain valid until natural expiry. Details in [ADR 0008](docs/adr/0008-ca-rotation.md).
- **Multi-operator** — local accounts, OIDC (Keycloak / Authentik / Okta / …), TOTP 2FA with recovery codes, configurable self-registration, per-operator API keys with atomic disable.
- **Per-operator CAs** — each operator's networks form an isolated trust domain; non-admin operators cannot see or sign against another operator's CA. Network and host creation is gated on the operator owning at least one CA.
- **Zero-trust enrollment** — hosts join with a single-use token; private keys never leave the host. Mobile hosts (iOS / Android) enroll via a self-contained QR code bundle.
- **Auto-rotation** — agent polls the server, atomically writes new certs/config (temp + fsync + rename), reloads Nebula via `SIGHUP`. Agent supports idle-standby mode and a first-class `enroll` subcommand.
- **Multi-address overlays** — networks and hosts can carry multiple overlay IPs (e.g. for dual-stack or multi-segment routing).
- **Per-host advanced overrides** — `listen_host`, `mtu`, `tun_device`, `punchy`, `unsafe_routes` opt-in per host without touching the network default. Host records are editable via UI/API after creation (`PATCH /api/v1/hosts/{id}`).
- **Audit trail** — every mutating UI / API / CLI call is recorded with actor, action, target, plus a stable `ca_id` on host events.
- **Per-network firewall rules** — managed declaratively via API, distributed to all hosts.
- **Production-ready basics** — `/healthz`, `/readyz`, Prometheus exporter at `/metrics` (legacy `expvar` view at `/debug/vars`), built-in cert-expiry alerter (audit + webhook + per-host Prometheus gauge), structured `slog` logs, optional in-process TLS, SQLite (WAL) with tracked migrations.
- **Tiny footprint** — two static binaries (~15–25 MiB each), SQLite, no external deps. Runs on a $5 VM.

</details>

<a name="architecture"></a>
## Architecture

One VM, two binaries:

```
┌──────────┐   REST/UI   ┌─────────────────────┐
│ operator │ ──────────▶ │   nebula-mgmt       │
└──────────┘   (HTTPS)   │  ┌───────────────┐  │
                         │  │ chi API       │  │
┌──────────┐   poll      │  │ web UI (htmx) │  │
│ nebula-  │ ──────────▶ │  │ PKI + store   │  │
│ agent    │ ◀────────── │  │ (SQLite WAL)  │  │
│ + nebula │   updates   │  └───────────────┘  │
└──────────┘             └─────────────────────┘
   each host                  one VM / container
```

- `nebula-mgmt` — management server (HTTP API + web UI + CLI subcommands)
- `nebula-agent` — runs on each Nebula host, polls for updates, atomically rewrites Nebula config, `SIGHUP`s Nebula

<details>
<summary><strong>Install</strong> — Linux packages, prebuilt binaries, Docker, from source</summary>
<a name="install"></a>


nebula-mesh ships **two** static binaries. Install whichever you need on each machine:

| Binary | Where it runs |
|---|---|
| `nebula-mgmt` | one server (the control plane) |
| `nebula-agent` | every Nebula host, next to `nebula` |

Pick an install method below. The examples assume `VERSION=0.3.2` — replace with the latest from the [releases page](https://github.com/juev/nebula-mesh/releases/latest). Each release ships a `checksums.txt` (SHA-256).

### Debian / Ubuntu (`.deb`)

```sh
VERSION=0.3.2
ARCH=$(dpkg --print-architecture)   # amd64 | arm64 | armhf (agent only)

# Server (control plane):
curl -fsSLO "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/nebula-mgmt_${VERSION}_linux_${ARCH}.deb"
sudo apt install -y "./nebula-mgmt_${VERSION}_linux_${ARCH}.deb"

# Agent (each Nebula host):
curl -fsSLO "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/nebula-agent_${VERSION}_linux_${ARCH}.deb"
sudo apt install -y "./nebula-agent_${VERSION}_linux_${ARCH}.deb"
```

### RHEL / Fedora / Rocky / Alma (`.rpm`)

```sh
VERSION=0.3.2
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

sudo rpm -i "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/nebula-mgmt_${VERSION}_linux_${ARCH}.rpm"
sudo rpm -i "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/nebula-agent_${VERSION}_linux_${ARCH}.rpm"
```

**What the package does.** Installs the binary to `/usr/bin/`, the systemd unit to `/lib/systemd/system/`, and an example config at `/etc/nebula-{mgmt,agent}/`. The service is **not** auto-started — run `nebula-mgmt init` (server) or `nebula-agent --server URL --token TOK` (agent) first, then `sudo systemctl enable --now nebula-{mgmt,agent}`. Configs are marked `noreplace`, so upgrades preserve your edits. `apt purge` / `dnf remove --purge` keeps `/etc/nebula-agent` and `/etc/nebula` so host keys survive accidental removal.

### Prebuilt binaries (other Linux, macOS, FreeBSD, Windows)

Download a tarball from the [releases page](https://github.com/juev/nebula-mesh/releases/latest) and extract:

```sh
VERSION=0.3.2
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Pick BIN=nebula-mgmt (server) or BIN=nebula-agent (host)
BIN=nebula-mgmt
curl -fsSL "https://github.com/juev/nebula-mesh/releases/download/v${VERSION}/${BIN}_${VERSION}_${OS}_${ARCH}.tar.gz" | tar -xz
```

Supported targets:

| | linux/amd64 | linux/arm64 | linux/armv7 | darwin/amd64 | darwin/arm64 | freebsd/amd64 | freebsd/arm64 | windows/amd64 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `nebula-mgmt` | ✅ | ✅ | – | ✅ | ✅ | – | – | – |
| `nebula-agent` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Docker

```sh
# Server:
docker run -d --name nebula-mgmt \
  -p 8080:8080 \
  -v nebula-mgmt-data:/var/lib/nebula-mgmt \
  -v nebula-mgmt-etc:/etc/nebula-mgmt \
  -e NEBULA_MGMT_MASTER_KEY \
  ghcr.io/juev/nebula-mgmt:latest

# Agent (typically sidecar to nebula, sharing the same PID namespace):
docker run -d --name nebula-agent \
  -v /etc/nebula-agent:/etc/nebula-agent \
  -v /etc/nebula:/etc/nebula \
  ghcr.io/juev/nebula-agent:latest
```

Images: `ghcr.io/juev/nebula-mgmt`, `ghcr.io/juev/nebula-agent`. Tags: `:latest` and `:X.Y.Z` (semver, no `v` prefix). See [Packages](https://github.com/juev?tab=packages&repo_name=nebula-mesh).

### From source

Requires Go 1.26+.

```sh
git clone https://github.com/juev/nebula-mesh
cd nebula-mesh
make build   # → bin/nebula-mgmt, bin/nebula-agent
```

Verify install with `nebula-mgmt version` / `nebula-agent --version`.

Lifecycle references: [`docs/server.md`](docs/server.md) (server), [`docs/agent.md`](docs/agent.md) (agent).

</details>

<details>
<summary><strong>Quickstart</strong> — run the server, enroll a host, manage from the CLI</summary>
<a name="quickstart"></a>


### Run the server

```sh
sudo mkdir -p /var/lib/nebula-mgmt /etc/nebula-mgmt
sudo cp configs/server.example.yml /etc/nebula-mgmt/server.yml

# Generate a master key for CA encryption (required) and export it.
export NEBULA_MGMT_MASTER_KEY=$(openssl rand -base64 32)

# One-time: initializes the database and provisions an admin-default CA.
sudo -E bin/nebula-mgmt init --config /etc/nebula-mgmt/server.yml

# Serve.
sudo -E bin/nebula-mgmt serve --config /etc/nebula-mgmt/server.yml
```

Open `http://localhost:8080/ui/` — log in as `admin` with the password configured in `ui_password` (falls back to the API key shown by `init`).

Non-interactive deployments (systemd, Docker): set `NEBULA_MGMT_MASTER_KEY` via environment variable or `master_key` in `server.yml`.

### Enroll a host

**Server / desktop / VM** — create a host record on the server (CLI or Web UI), grab the one-time enrollment token, run `nebula-agent` on the host with `--server` + `--token` once, then put the agent under systemd. The agent keeps `host.crt` / `host.key` / `host.signing.key` / `ca.crt` / `config.yml` in sync, signs every poll with the per-host Ed25519 key generated at enrollment (ADR 0004), and exits 0 when the server returns `403 revoked` or `410 gone`.

**iOS / Android** — create the host with type **Mobile bundle**; the Web UI then renders a QR-code bundle (cert + key + CA + config) that the official Nebula mobile app scans to enrol in one step. No agent runs on the device; rotation requires re-issuing a new bundle. See [`docs/agent.md`](docs/agent.md) for the bundle format.

> Full nebula-agent operations guide: [`docs/agent.md`](docs/agent.md) — installation, configuration, enrollment + systemd hand-off, signed-poll headers, force-rotate / re-enroll endpoints, troubleshooting, upgrade, and security notes.

### Manage hosts from the CLI

```sh
# List hosts (optionally filter by network)
nebula-mgmt host list --server https://mgmt.example.com:8080 --api-key "$API_KEY"

# Block a host (revokes cert via blocklist, status → blocked)
nebula-mgmt host block   --server ... --api-key "$API_KEY" --id "$HOST_ID"

# Unblock a host (status → pending; re-enrollment required for a new cert)
nebula-mgmt host unblock --server ... --api-key "$API_KEY" --id "$HOST_ID"

# Delete a host (also blocklists any existing cert)
nebula-mgmt host delete  --server ... --api-key "$API_KEY" --id "$HOST_ID"
```

</details>

<details>
<summary><strong>Operators, auth, and tenancy</strong> — accounts, TOTP, OIDC, self-registration, per-operator CAs</summary>
<a name="operators-auth-and-tenancy"></a>


Each interactive admin should have their own operator account and per-operator API key. On `nebula-mgmt init`, an admin operator is seeded from `ui_password` (or, if that is empty, an auto-generated value used solely for the admin's bcrypt password hash). The admin's first operator API key is generated freshly inside init and printed to stdout once — capture it then; the server does not persist the plaintext to disk. Lost the key? Run `nebula-mgmt ops mint-admin-key --config <path>` to mint a new admin API key.

### Manage operators

```sh
# List operators
nebula-mgmt user list --server ... --api-key "$ADMIN_KEY"

# Create another operator (admin-only API)
nebula-mgmt user create --server ... --api-key "$ADMIN_KEY" \
  --username alice --password 's3cret!' --display-name "Alice"

# Per-operator API key (token shown once)
nebula-mgmt apikey create --server ... --api-key "$ADMIN_KEY" \
  --operator "$ALICE_ID" --name laptop-cli
nebula-mgmt apikey revoke --server ... --api-key "$ADMIN_KEY" \
  --operator "$ALICE_ID" --id "$KEY_ID"

# Disable / re-enable an operator — invalidates sessions and API keys atomically
nebula-mgmt user disable --server ... --api-key "$ADMIN_KEY" --id "$ALICE_ID"
nebula-mgmt user enable  --server ... --api-key "$ADMIN_KEY" --id "$ALICE_ID"
```

Audit log entries (`/api/v1/audit-log`) record the actor for every mutating operator/host action.

### Two-factor authentication (TOTP)

Open `/ui/2fa`, click **Enable 2FA**, scan the displayed `otpauth://` URL with 1Password / Bitwarden / Google Authenticator / Aegis / Authy / any compatible app, and confirm with a 6-digit code. The server then shows ten one-time recovery codes — save them offline. On the next login the UI asks for the 6-digit code (or one recovery code) after the password. Disabling 2FA requires re-confirming the current password. All sensitive operations (`operator.2fa.enabled`, `disabled`, `regen_codes`, `failed`, `verified`) appear in the audit log. API tokens are unaffected.

**Admin enforcement.** Set `enforce_2fa: true` in `server.yml` (or `PATCH /api/v1/settings` with `{"enforce_2fa": true}` at runtime). Every local operator without TOTP is then routed to `/ui/2fa/required` after a successful password login and cannot reach any other UI page until enrolment finishes. `POST /ui/2fa/disable` returns `403` while the toggle is on and writes an `operator.2fa.enforced.disable_blocked` audit entry. OIDC operators are exempt — their second factor lives at the IdP.

### Single sign-on via OIDC

Configure an `oidc:` block in `server.yml` (see `configs/server.example.yml`) to enable operator login through Keycloak / Authentik / Dex / Google Workspace / Okta / any standard OpenID Connect provider. The login page then shows a **Sign in with SSO** button alongside the local form.

```yaml
oidc:
  enabled: true
  issuer: "https://keycloak.example.com/realms/nebula"
  client_id: "nebula-mesh"
  client_secret: "<from your provider>"
  redirect_url: "https://mgmt.example.com:8080/ui/oidc/callback"
  scopes: ["openid", "profile", "email", "groups"]
  allowed_groups: ["nebula-admins"]
```

The first successful login for an unknown subject creates a local operator record (`auth_provider=oidc`) tied to the `issuer+subject` pair. Local and OIDC users coexist; revoke an OIDC user by disabling the local record or removing them in the IdP.

### Configurable self-registration

By default only administrators can create operator accounts. Set `allow_self_registration: true` in `server.yml`, or flip it from **Settings → Allow self-registration** in the Web UI, to let unauthenticated visitors sign up via `/ui/register`. Server-side checks gate the endpoint independently of the UI, so flipping the flag is enough to block self-registration. Self-registered operators get the `user` role; the operator-management API (`POST /api/v1/operators`, `disable`, etc) requires `role: admin`.

### Settings page

`/ui/settings` (admin-only — non-admins are 403'd, and the sidebar entry is hidden) exposes the runtime knobs administrators can flip without restarting the server: admin-enforced 2FA, self-registration, password policy (min length, required character classes, common-password blocklist, username block), and log level. Saved values land in the `server_settings` table; every save writes a `settings.update` audit-log entry. `server.yml` becomes the bootstrap snapshot — `allow_self_registration:` and `enforce_2fa:` are seeded once and then the DB row wins. Secrets (`master_key`, OIDC client secret, TLS file paths) stay in `server.yml` only.

### Per-operator CAs

With `NEBULA_MGMT_MASTER_KEY` configured, operators can run their networks under isolated CAs. Mint, browse, retire, and delete CAs from the CLI (below), the REST API (`/api/v1/cas*`), or the Web UI at `/ui/cas` — every flow shares the same ownership check, so a non-admin operator only sees the CAs they own.

```sh
# Create a CA scoped to a real operator (the legacy config key is denied)
nebula-mgmt ca create --server ... --api-key "$OPERATOR_KEY" --name tenant-a
# → prints CA id + fingerprint

nebula-mgmt ca list   --server ... --api-key "$OPERATOR_KEY"
nebula-mgmt ca delete --server ... --api-key "$OPERATOR_KEY" --id "$CA_ID"
```

Non-admin operators see and manage only the CAs they own; admins see all. Hosts enrolled under a tenant CA receive **that** CA's certificate, not the default one. Audit log entries (`ca.created`, `ca.deleted`, plus existing `host.*` events with the host's `ca_id`) record both the actor and the affected CA. See [ADR 0002](docs/adr/0002-per-operator-cas.md) for the encryption-at-rest design.

**CA rotation**: when a CA approaches its expiry (≤20% lifetime remaining), the UI shows a warning badge on the CA pages. Operators can click **Rotate** to create a successor CA; existing host certificates remain valid until their natural expiry. CLI: `nebula-mgmt ca rotate <id>`. Optional opt-in auto-rotation: set `ca_auto_rotate.enabled: true` in `server.yaml` to enable automatic rotation (disabled by default). See [ADR 0008](docs/adr/0008-ca-rotation.md) for the hybrid model and trust bundle distribution.

</details>

<details>
<summary><strong>Deployment</strong> — Docker / systemd / TLS, and how to back up the DB + master key</summary>
<a name="deployment"></a>


- **Docker** — `docker build -t nebula-mgmt .` (Dockerfile in repo).
- **systemd** — unit files in [`deploy/systemd/`](deploy/systemd/).
- **TLS** — set `tls_cert` + `tls_key` for in-process TLS, or front with nginx/caddy/traefik. Working snippets for all three live in [`deploy/reverse-proxy/`](deploy/reverse-proxy/) and ship inside the `.deb`/`.rpm` at `/usr/share/doc/nebula-mgmt/reverse-proxy/`. Each is opinionated, preserves `X-Forwarded-For`, and disables buffering on `/ui/events` so the SSE feed reaches the browser in real time.
- **Rate limiting** — on by default. The Web UI, auth endpoints, `/api/v1/enroll`, and the bearer-authenticated admin API each run their own per-IP token bucket. Defaults: 5 req/s on login forms (burst 10), 2 req/s on enrolment (burst 5), 30 req/s on UI + admin API (burst 60), 60 req/s on agent polls (burst 120). Health (`/healthz`, `/readyz`, `/metrics`, `/debug/vars`, `/favicon.ico`, `/static/*`) is exempt. Run behind a reverse proxy? Set `rate_limit.trust_proxy_header: true` so the limiter keys on `X-Forwarded-For` instead of the proxy's connection address.

### Backups & key handling

Per [ADR 0002](docs/adr/0002-per-operator-cas.md) (which removed [ADR 0001](docs/adr/0001-ca-key-storage.md)), CA private keys live encrypted inside SQLite using envelope encryption. The master key (`NEBULA_MGMT_MASTER_KEY`, 32 random bytes, base64-encoded) is supplied at startup and **never written to disk or the DB**. Backups collapse to a single file:

```sh
sudo cp /var/lib/nebula-mgmt/nebula.db /backups/nebula-$(date +%F).db
```

Keep `NEBULA_MGMT_MASTER_KEY` in your secret manager — both the DB and the master key are required to mint a certificate.

The server administrator can decrypt every CA on the box (the master key is in process memory while the server runs). We accept this for the single-binary deployment story — see [ADR 0003](docs/adr/0003-ca-encryption-model.md) for the alternatives (operator-derived KEK, zero-knowledge, external signer) and why we did not adopt them today.

</details>

<a name="endpoints"></a>
## Endpoints

The router (issue #69) splits the listener three ways: `/api/` for the API surface, root + `/ui/` for the Web UI, and a fixed list of ops paths kept at the root for monitoring scrapes. The bare `/` redirects browsers to `/ui/`.

| Prefix | Path | Auth | Purpose |
|---|---|---|---|
| UI | `/` | (redirect) | 302 to `/ui/` so first-time visitors land on the dashboard. |
| UI | `/ui/` | session cookie | web UI (rate-limited, see below). |
| UI | `/static/*`, `/favicon.ico` | none | UI assets. |
| API | `/api/v1/enroll` | enrollment token + signing public key | agent first-contact. |
| API | `/api/v1/agent/updates` | signed PoP headers (ADR 0004) | agent poll. |
| API | `/api/v1/...` | `Bearer <api_key>` | admin REST API. |
| Ops | `/healthz` | none | liveness. |
| Ops | `/readyz` | none | readiness (DB reachable). |
| Ops | `/metrics` | none | Prometheus exposition (see [`internal/api/metrics.go`](internal/api/metrics.go)). Disable via `metrics.prometheus: false`. |
| Ops | `/debug/vars`, `/debug/pprof/*` | none | Go `expvar` / pprof. |
| Ops | `/health` | none | legacy alias for `/healthz`. |

Full route list in [`internal/api/server.go`](internal/api/server.go) and [`internal/web/web.go`](internal/web/web.go).

### Per-endpoint rate-limit groups

On by default; configurable in `server.yml`. Each group is a separate per-IP token bucket:

| Group | Default (req/s / burst) | Endpoints |
|---|---|---|
| `auth` | 5 / 10 | `POST /ui/login`, `POST /ui/login/totp`, `POST /ui/register` |
| `ui` | 30 / 60 | every other `/ui/...` page + the admin REST API under `/api/v1/...` |
| `enroll` | 2 / 5 | `POST /api/v1/enroll` |
| `agent_poll` | 60 / 120 | `GET /api/v1/agent/updates` |

Ops endpoints (`/healthz`, `/readyz`, `/metrics`, `/debug/`, `/favicon.ico`, `/static/*`) are exempt so scrapes never get 429s. Behind a reverse proxy, set `rate_limit.trust_proxy_header: true` to key the buckets on `X-Forwarded-For` instead of the proxy's loopback connection.

### Optional: mTLS on the UI only

`crypto/tls.ClientAuth` is a listener-level setting, so per-route client-cert verification lives in the reverse proxy rather than in `nebula-mgmt` itself. Each snippet in [`deploy/reverse-proxy/`](deploy/reverse-proxy/) ships a commented-out block that gates `/ui/` (and `/`) behind a client cert while leaving `/api/` and the ops endpoints reachable without one — agents and Prometheus do not present operator certificates.

<a name="status"></a>
## Status

**Beta.** Core flows (init, enroll, poll, rotate, revoke, audit, multi-CA) are covered by unit + integration tests with `-race`. API surface is not yet frozen — expect breaking changes until `v1.0.0`. Please open issues for anything rough.

<a name="security"></a>
## Security

- **Authentication.** Interactive logins are bcrypt-verified against the operator's password; sessions are DB-backed and revoked atomically on `user disable`. Optional TOTP 2FA + recovery codes. Optional OIDC SSO.
- **Authorization.** Operator-management API and CA-management API require `role: admin`; non-admin operators can only see and act on the CAs they own.
- **API keys.** Per-operator, stored as SHA-256 hashes — disable an operator and every key revokes in the same transaction. All admin authentication runs through DB-backed operator_api_keys (SHA-256 hashed).
- **CA key material.** Stored encrypted at rest in SQLite under a process-wide AES-256-GCM master key (`NEBULA_MGMT_MASTER_KEY`), supplied at startup and never persisted. See [ADR 0002](docs/adr/0002-per-operator-cas.md) for the threat-model discussion and [ADR 0003](docs/adr/0003-ca-encryption-model.md) for the operator-derived-KEK / zero-knowledge alternatives we evaluated and deferred.
- **Transport.** Always run the management server behind TLS — set `tls_cert` + `tls_key`, or front with nginx/caddy/traefik.
- **Disclosure.** Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Contributing

Issues, PRs, and discussions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and `make test && make lint` before opening a PR.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

Built on top of [`slackhq/nebula`](https://github.com/slackhq/nebula). nebula-mesh is an independent project and is not affiliated with or endorsed by Slack.
