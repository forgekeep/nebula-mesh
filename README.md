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

### From a release (Linux / macOS, amd64 / arm64)

```sh
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
TAG=$(curl -fsSL https://api.github.com/repos/juev/nebula-mesh/releases/latest | grep -m1 tag_name | cut -d'"' -f4)
curl -fsSL "https://github.com/juev/nebula-mesh/releases/download/${TAG}/nebula-mesh_${TAG#v}_${OS}_${ARCH}.tar.gz" | tar -xz
# → nebula-mgmt, nebula-agent in the current directory
```

Or grab a specific build from [Releases](https://github.com/juev/nebula-mesh/releases). Each release ships `checksums.txt` (SHA-256).

### From source

Requires Go 1.26+.

```sh
make build           # outputs bin/nebula-mgmt and bin/nebula-agent
```

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

## Deployment

- **Docker** — `docker build -t nebula-mgmt .` (Dockerfile in repo).
- **systemd** — unit files in [`deploy/systemd/`](deploy/systemd/).
- **TLS** — set `tls_cert` + `tls_key` for in-process TLS, or front with nginx/caddy/traefik.

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
