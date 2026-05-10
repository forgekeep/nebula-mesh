# nebula-mgmt

Self-hosted management platform for [Nebula](https://github.com/slackhq/nebula) mesh networks. Provides a REST API, web UI, CLI, and an enrollment agent for issuing/rotating certificates and distributing Nebula configuration to hosts.

Two binaries:

- `nebula-mgmt` — management server (HTTP API + web UI + CLI)
- `nebula-agent` — runs on each Nebula host, polls the server for updates and reloads Nebula via SIGHUP

## Build

Requires Go 1.26+.

```sh
make build
# binaries in ./bin/
```

Test and lint:

```sh
make test    # go test -v -race ./...
make lint    # golangci-lint run ./...
```

## Quickstart (server)

```sh
# 1. Initialize: creates CA, generates 32-byte API key, writes config.
sudo mkdir -p /var/lib/nebula-mgmt /etc/nebula-mgmt
sudo cp configs/server.example.yml /etc/nebula-mgmt/server.yml
sudo bin/nebula-mgmt init --config /etc/nebula-mgmt/server.yml
# Prompts for a CA passphrase. The generated API key is written back
# into the config file (api_key field).

# 2. Run the server.
sudo bin/nebula-mgmt serve --config /etc/nebula-mgmt/server.yml
# Prompts for the CA passphrase on each start.
```

For non-interactive deployments (systemd, Docker without `-it`), set the CA passphrase via the `NEBULA_MGMT_CA_PASSPHRASE` env var. The server refuses to start if stdin is not a TTY and the env var is unset.

By default the server listens on `:8080` over plain HTTP. For production:

- Set `tls_cert` and `tls_key` in the config to terminate TLS in-process, **or**
- Run behind a TLS-terminating reverse proxy (nginx, caddy, traefik) and keep `tls_cert`/`tls_key` empty.

## Endpoints

- `/healthz` — liveness (always 200 if the process is running)
- `/readyz` — readiness (200 if DB reachable, 503 otherwise)
- `/metrics` — runtime stats via stdlib `expvar` (cmdline, memstats)
- `/health` — legacy alias of `/healthz`
- `/ui/` — web UI (basic auth, password from `ui_password` or `api_key`)
- `/api/v1/enroll` — public, agent enrollment with token
- `/api/v1/agent/updates` — public, agent poll endpoint
- `/api/v1/...` — protected, requires `Authorization: Bearer <api_key>`

See `internal/api/server.go` for the full route list.

## Quickstart (agent)

On each Nebula host:

```sh
# 1. Create a host on the server (requires API key):
nebula-mgmt host create \
  --server https://mgmt.example.com:8080 \
  --api-key "$API_KEY" \
  --network "$NETWORK_ID" \
  --name "web-1" \
  --ip "192.168.100.10"
# Prints an enrollment token.

# 2. On the host: enroll once.
sudo cp configs/agent.example.yml /etc/nebula-agent/agent.yml
sudo nebula-agent enroll \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN" \
  --data-dir /etc/nebula
# Writes host.crt, host.key, ca.crt, config.yml to data-dir.

# 3. Start the polling agent (after Nebula is running).
sudo nebula-agent run --config /etc/nebula-agent/agent.yml
```

The agent polls the server every `poll_interval` and writes updates atomically (temp file + fsync + rename), then sends `SIGHUP` to the Nebula process via `nebula_pid_file`.

## Deployment

- **Docker** — `Dockerfile` provided for the server. Build: `docker build -t nebula-mgmt .`
- **systemd** — unit files in `deploy/systemd/`. Copy to `/etc/systemd/system/`, then `systemctl enable --now nebula-mgmt`.
- **TLS** — see configuration above.

## Architecture

- `cmd/` — binary entrypoints
- `internal/config` — YAML config loading and atomic save
- `internal/pki` — wraps `slackhq/nebula/cert` (CA create/load/sign, blocklist)
- `internal/store` — SQLite persistence (WAL, foreign keys, embedded migrations)
- `internal/api` — REST API (chi router, bearer auth, audit log, firewall rules)
- `internal/web` — server-rendered UI (Go templates + htmx)
- `internal/agent` — poll loop + atomic file writes + SIGHUP signaling
- `internal/configgen` — Nebula config.yml generator from templates
- `internal/cli` — `init`, `serve`, `host`, `network` subcommands
- `tests/integration` — end-to-end flow

## Security notes

- API key has full admin rights — store it like a database password (file mode 0600 enforced by `SaveServerConfig`).
- CA private key is encrypted with a passphrase entered interactively at init/start time. Do not store the passphrase in environment variables or config files in production.
- Always run the management server behind TLS (in-process or reverse proxy).
- Nebula firewall rules are set per network in the API; the default policy allows only ICMP inbound.

## License

MIT
