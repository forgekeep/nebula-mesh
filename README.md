# nebula-mesh

> Self-hosted control plane for [Slack's Nebula](https://github.com/slackhq/nebula) mesh VPN — issue certificates, manage hosts, distribute config, and roll out changes from one place.

![Dashboard](docs/screenshots/dashboard.png)

<sub>More views: [hosts](docs/screenshots/hosts.png) · [host detail](docs/screenshots/host-detail.png) · [networks](docs/screenshots/networks.png)</sub>

[![CI](https://github.com/juev/nebula-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/juev/nebula-mesh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/juev/nebula-mesh?display_name=tag&sort=semver)](https://github.com/juev/nebula-mesh/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/juev/nebula-mesh.svg)](https://pkg.go.dev/github.com/juev/nebula-mesh)
[![Go Report Card](https://goreportcard.com/badge/github.com/juev/nebula-mesh)](https://goreportcard.com/report/github.com/juev/nebula-mesh)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/juev/nebula-mesh)](go.mod)

Nebula gives you a fast, mTLS-authenticated overlay network. But on its own, it leaves the operator to hand-roll certificate issuance, rotation, distribution and revocation — usually with shell scripts and a CA on a laptop. **nebula-mesh** is the missing management layer: a single Go binary plus an enrollment agent that turn Nebula into a self-service mesh you can run on one VM.

## Why

| | Hand-rolled scripts | DefinedNetworking (managed) | **nebula-mesh** |
|---|---|---|---|
| Self-hosted | ✅ | ❌ | ✅ |
| Web UI + REST API | ❌ | ✅ | ✅ |
| Cert rotation & revocation | manual | ✅ | ✅ |
| Single static binary | ✅ | n/a | ✅ |
| Cost | your time | per-host | free (MIT) |
| Lock-in | none | vendor | none |

## Features

- **Web UI + REST API + CLI** — one server, three interfaces. Built with chi + Go templates + htmx (no SPA build step).
- **PKI lifecycle** — CA on init (encrypted with passphrase), per-host certs signed via `slackhq/nebula/cert`, blocklist-backed revocation.
- **Zero-trust enrollment** — hosts join with a single-use token; private keys never leave the host.
- **Auto-rotation** — agent polls the server, atomically writes new certs/config (temp + fsync + rename), reloads Nebula via `SIGHUP`.
- **Audit trail** — every API mutation is recorded with actor, action, target.
- **Per-network firewall rules** — managed declaratively via API, distributed to all hosts.
- **Production-ready basics** — `/healthz`, `/readyz`, `expvar` metrics, structured `slog` logs, optional in-process TLS, SQLite (WAL) with embedded migrations.
- **Tiny footprint** — two static binaries (~15–25 MiB each), SQLite, no external deps. Runs on a $5 VM.

## Architecture

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

## Install

Each release ships **two** independent artifact sets — install only what you need on each machine.

| | Server (`nebula-mgmt`) | Agent (`nebula-agent`) |
|---|---|---|
| Where it runs | one VM / container — the control plane | every Nebula host — next to `nebula` |
| Binary tarball | `nebula-mgmt_<v>_<os>_<arch>.tar.gz` | `nebula-agent_<v>_<os>_<arch>.tar.gz` |
| Docker image | `ghcr.io/juev/nebula-mgmt` | `ghcr.io/juev/nebula-agent` |

### Prebuilt binary (Linux / macOS, amd64 / arm64)

```sh
# Pick one: BIN=nebula-mgmt   (control-plane VM)
#          BIN=nebula-agent   (every Nebula host)
BIN=nebula-mgmt
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
TAG=$(curl -fsSL https://api.github.com/repos/juev/nebula-mesh/releases/latest | grep -m1 tag_name | cut -d'"' -f4)
curl -fsSL "https://github.com/juev/nebula-mesh/releases/download/${TAG}/${BIN}_${TAG#v}_${OS}_${ARCH}.tar.gz" | tar -xz
```

Each release ships a `checksums.txt` with SHA-256 of every archive.

### Docker (linux/amd64, linux/arm64)

```sh
# Server:
docker run -d --name nebula-mgmt \
  -p 8080:8080 \
  -v nebula-mgmt-data:/var/lib/nebula-mgmt \
  -v nebula-mgmt-etc:/etc/nebula-mgmt \
  -e NEBULA_MGMT_CA_PASSPHRASE \
  ghcr.io/juev/nebula-mgmt:latest

# Agent (typically sidecar to nebula, sharing the same PID namespace):
docker run -d --name nebula-agent \
  -v /etc/nebula-agent:/etc/nebula-agent \
  -v /etc/nebula:/etc/nebula \
  ghcr.io/juev/nebula-agent:latest
```

Images are published to GitHub Container Registry with `:X.Y.Z` (semver, no `v` prefix) and `:latest` tags. See [Packages](https://github.com/juev?tab=packages&repo_name=nebula-mesh).

### From source

Requires Go 1.26+.

```sh
make build           # outputs bin/nebula-mgmt and bin/nebula-agent
```

After install, `nebula-mgmt version` and `nebula-agent --version` print the build version, short commit, and build date.

## Quickstart

### 1. Run the server

```sh
sudo mkdir -p /var/lib/nebula-mgmt /etc/nebula-mgmt
sudo cp configs/server.example.yml /etc/nebula-mgmt/server.yml

# One-time: creates CA, generates API key, persists both into the config.
sudo bin/nebula-mgmt init --config /etc/nebula-mgmt/server.yml

# Serve.
sudo bin/nebula-mgmt serve --config /etc/nebula-mgmt/server.yml
```

Open `http://localhost:8080/ui/` — log in with the API key shown by `init`.

Non-interactive deployments (systemd, Docker): set `NEBULA_MGMT_CA_PASSPHRASE` instead of typing the passphrase at start.

### 2. Enroll a host

```sh
# On the server — create a host record:
nebula-mgmt host create \
  --server https://mgmt.example.com:8080 \
  --api-key "$API_KEY" \
  --network "$NETWORK_ID" \
  --name web-1 --ip 192.168.100.10
# → prints an enrollment token

# On the host — one-time enrollment + start the polling agent:
sudo cp configs/agent.example.yml /etc/nebula-agent/agent.yml
sudo nebula-agent enroll \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN" \
  --data-dir /etc/nebula
sudo nebula-agent run --config /etc/nebula-agent/agent.yml
```

The agent now keeps `host.crt` / `host.key` / `ca.crt` / `config.yml` in sync and signals Nebula on changes.

> Full nebula-agent operations guide: [`docs/agent.md`](docs/agent.md) — installation, configuration, troubleshooting, upgrade, and security notes.

### 3. Manage hosts from the CLI

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

### 4. Manage operators (multi-user)

Each interactive admin should have their own operator account and per-operator
API key. On `nebula-mgmt init`, an `admin` operator is seeded from the config's
`ui_password` (or `api_key` as a fallback) and the config `api_key` is registered
as `admin`'s first API key.

```sh
# List operators
nebula-mgmt user list --server ... --api-key "$ADMIN_KEY"

# Create another operator
nebula-mgmt user create --server ... --api-key "$ADMIN_KEY" \
  --username alice --password 's3cret!' --display-name "Alice"

# Create a per-operator API key (token shown once)
nebula-mgmt apikey create --server ... --api-key "$ADMIN_KEY" \
  --operator "$ALICE_ID" --name laptop-cli

# Revoke a key
nebula-mgmt apikey revoke --server ... --api-key "$ADMIN_KEY" \
  --operator "$ALICE_ID" --id "$KEY_ID"

# Disable / re-enable an operator (invalidates sessions and API keys atomically)
nebula-mgmt user disable --server ... --api-key "$ADMIN_KEY" --id "$ALICE_ID"
nebula-mgmt user enable  --server ... --api-key "$ADMIN_KEY" --id "$ALICE_ID"
```

Audit log entries (`/api/v1/audit-log`) record the actor for every mutating
operator/host action.

### 5. Enable two-factor authentication (TOTP)

Open `/ui/2fa`, click **Enable 2FA**, scan the displayed `otpauth://` URL with
1Password / Bitwarden / Google Authenticator / Aegis / Authy / any compatible
app, and confirm with a 6-digit code. The server then shows ten one-time
recovery codes — save them offline.

On the next login the UI asks for the 6-digit code (or one recovery code) after
the password. Disabling 2FA requires re-confirming the current password. All
sensitive operations (`operator.2fa.enabled`, `disabled`, `regen_codes`,
`failed`, `verified`) appear in the audit log.

API tokens are not affected — they continue to authenticate non-interactive
clients.

### 6. Single sign-on via OIDC (optional)

Configure an `oidc:` block in `server.yml` (see `configs/server.example.yml`)
to enable operator login through Keycloak / Authentik / Dex / Google
Workspace / Okta / any standard OpenID Connect provider. Once enabled, the
login page shows a **Sign in with SSO** button alongside the local form.

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

The first successful login for an unknown subject creates a local operator
record (auth_provider=oidc) tied to the issuer+subject pair. Audit log
entries record the operator's username for every action. Local and OIDC
users coexist; revoking access for an OIDC user is done by disabling the
local record or removing them in the IdP.

## Deployment

- **Docker** — `docker build -t nebula-mgmt .` (Dockerfile in repo).
- **systemd** — unit files in [`deploy/systemd/`](deploy/systemd/).
- **TLS** — set `tls_cert` + `tls_key` for in-process TLS, or front with nginx/caddy/traefik.

### Backups

Two artifacts must be backed up together: the CA key material in `data_dir`
and the SQLite database in `db_path`. The CA passphrase is intentionally
**not** stored on disk — keep it in your secret manager.

```sh
sudo tar --xattrs -czf /backups/nebula-mgmt-$(date +%F).tar.gz \
    /var/lib/nebula-mgmt/ca.crt \
    /var/lib/nebula-mgmt/ca.key \
    /var/lib/nebula-mgmt/nebula.db
```

See [ADR 0001](docs/adr/0001-ca-key-storage.md) for the rationale behind
keeping the CA key on the filesystem instead of in the database.

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `/healthz` | none | liveness |
| `/readyz` | none | readiness (DB reachable) |
| `/metrics` | none | `expvar` runtime stats |
| `/ui/` | session cookie | web UI |
| `/api/v1/enroll` | enrollment token | agent first-contact |
| `/api/v1/agent/updates` | host cert | agent poll |
| `/api/v1/...` | `Bearer <api_key>` | admin REST API |

Full route list in [`internal/api/server.go`](internal/api/server.go).

## Status

**Beta.** Core flows (init, enroll, poll, rotate, revoke, audit) are covered by unit + integration tests with `-race`. API surface is not yet frozen — expect breaking changes until `v1.0.0`. Please open issues for anything rough.

## Roadmap

- [ ] Lighthouse auto-assignment based on host role
- [ ] Multi-operator auth (OIDC / per-user API keys)
- [ ] Prometheus exporter (today: `expvar`)
- [ ] Built-in cert expiry alerts
- [ ] Bootstrap-from-cloud-init recipes (Terraform / Ansible modules)
- [ ] Web UI: live host status (currently htmx polling)

Want to help? See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

- API key has full admin rights — file mode `0600` is enforced on save.
- CA private key is encrypted with a passphrase entered interactively at `init` / `serve`. In production, prefer `NEBULA_MGMT_CA_PASSPHRASE` injected via a secret manager.
- Always run the management server behind TLS.
- Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Contributing

Issues, PRs, and discussions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and `make test && make lint` before opening a PR.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

Built on top of [`slackhq/nebula`](https://github.com/slackhq/nebula). nebula-mesh is an independent project and is not affiliated with or endorsed by Slack.
