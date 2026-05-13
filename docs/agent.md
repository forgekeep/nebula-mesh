# nebula-agent

The `nebula-agent` is the client-side counterpart to `nebula-mgmt`. It enrolls a host
into a network, polls the management server for configuration updates, writes Nebula's
`config.yml`, `host.crt`, `host.key`, and `ca.crt` atomically, and signals `nebula` to
pick up changes.

This document covers production usage — installation, configuration, day-2 operations
and troubleshooting. The 30-second walkthrough lives in the project [README](../README.md).

## How it works

```
┌──────────────────┐        HTTPS (Bearer cert)        ┌────────────────────┐
│   nebula-agent   │  ───────────────────────────────▶ │     nebula-mgmt    │
│  (runs alongside │  GET /api/v1/agent/updates        │   (server + UI)    │
│   nebula on a    │  ◀───────────────────────────────  │                    │
│       host)      │     config.yml + host cert + CA   │                    │
└──────────────────┘                                    └────────────────────┘
        │
        │ atomic write
        ▼
   /etc/nebula/{config.yml, host.crt, host.key, ca.crt}
        │
        │ SIGHUP (if pid file present)
        ▼
   nebula.service
```

The agent does **not** require a Nebula tunnel to reach the management server; it
talks plain HTTPS over the regular network. Once Nebula is up, the agent can keep
running and continue to update certificates as they approach expiry.

## Runtime requirements

- A Linux/BSD host with the `nebula` binary already installed (the agent does not
  manage the Nebula process itself, only its config and certs).
- Outbound HTTPS access to the management server's `--server` URL.
- Permission to read & write the agent's `data_dir` (`/etc/nebula` by default).
- If signalling Nebula via PID file, permission to send `SIGHUP` to that PID
  (typically root, or `CAP_KILL`).
- ~10 MB of disk for the binary; runtime memory < 20 MB.

## Installation

### Supported release matrix

Each tagged release ships pre-built `nebula-agent` binaries for the OS/arch
combinations listed below. The list aligns with the platforms Slack Nebula
itself supports for production use; less common Nebula targets (mips, ppc64,
openbsd, netbsd, ios, android) are *not* published — build from source if
you need them.

| OS | Architecture | Archive suffix | Notes |
|---|---|---|---|
| linux | amd64 | `linux_amd64.tar.gz` | Tested. Recommended default. |
| linux | arm64 | `linux_arm64.tar.gz` | Tested. Raspberry Pi 4/5 64-bit OS, AWS Graviton, … |
| linux | arm (v7) | `linux_armv7.tar.gz` | Built, not regularly tested. Raspberry Pi 3 / 32-bit Pi OS. |
| darwin | amd64 | `darwin_amd64.tar.gz` | Intel Macs. |
| darwin | arm64 | `darwin_arm64.tar.gz` | Apple Silicon. |
| freebsd | amd64 | `freebsd_amd64.tar.gz` | Built. Use with the FreeBSD Nebula port. |
| freebsd | arm64 | `freebsd_arm64.tar.gz` | Built, not regularly tested. |
| windows | amd64 | `windows_amd64.zip` | Built. SIGHUP-based reload is unavailable on Windows — leave `nebula_pid_file` empty and restart Nebula manually. |

Unsupported targets and reasoning:

- `windows/arm64` — buildable, but no demand and no test coverage. Open an
  issue if you need it.
- `linux/mips*`, `linux/ppc64*`, `linux/riscv64` — Nebula upstream builds for
  these; we do not yet, to keep the release size manageable. Build from
  source: `GOOS=linux GOARCH=riscv64 go build ./cmd/nebula-agent`.
- `openbsd`, `netbsd`, `ios`, `android` — operationally impractical for a
  long-running polling agent.

### 1a. From a Linux distro package (recommended on Debian / Ubuntu / RHEL)

Each tagged release publishes `.deb` and `.rpm` packages for `amd64` and `arm64`:

```sh
# Debian / Ubuntu
curl -fsSL -O https://github.com/juev/nebula-mesh/releases/download/<version>/nebula-agent_<version>_linux_amd64.deb
sudo apt install ./nebula-agent_<version>_linux_amd64.deb

# RHEL / Fedora / CentOS Stream / Rocky / Alma
sudo rpm -i https://github.com/juev/nebula-mesh/releases/download/<version>/nebula-agent_<version>_linux_amd64.rpm
```

The package:

- installs `/usr/bin/nebula-agent` and `/lib/systemd/system/nebula-agent.service`;
- ships an example config at `/etc/nebula-agent/agent.example.yml`;
- creates the `nebula-agent` system user/group for future hardening;
- **does not** create `/etc/nebula-agent/agent.yml`, start, or enable the service — run `nebula-agent --server URL --token TOK` once to write the config + enroll, then `systemctl enable --now nebula-agent`;
- on upgrade, leaves `/etc/nebula-agent/agent.yml` and `/etc/nebula/{host.crt,host.key,ca.crt,config.yml}` untouched;
- on removal, stops and disables the service but keeps `/etc/nebula-agent` and `/etc/nebula` intact (so host keys survive accidental removals). `apt purge` / `dnf remove --purge` will additionally delete the system user.

Checksums for every artifact are published in `checksums.txt` next to the package.

### 1b. From a release archive (other platforms)

For platforms without a native package (macOS, FreeBSD, Windows, Linux/arm v7),
replace `<version>` and `<platform>` as needed:

```sh
curl -fsSL -o nebula-agent.tar.gz \
  https://github.com/juev/nebula-mesh/releases/download/<version>/nebula-agent_<platform>.tar.gz
tar -xzf nebula-agent.tar.gz
sudo install -m 0755 nebula-agent /usr/local/bin/
```

Verify:

```sh
nebula-agent version
```

### 2. As a systemd service

A reference unit lives at [`deploy/systemd/nebula-agent.service`](../deploy/systemd/nebula-agent.service).
It pulls config from `/etc/nebula-agent/agent.yml`, runs as root (needed for `chmod 0600`
on the host key and for sending `SIGHUP` to Nebula), and is hardened with the usual
`ProtectSystem=strict` + `SystemCallFilter` knobs.

```sh
sudo install -m 0644 deploy/systemd/nebula-agent.service /etc/systemd/system/
# First run enrolls the host and writes /etc/nebula-agent/agent.yml (mode 0600):
sudo nebula-agent --server https://mgmt.example.com:8080 --token "$ENROLL_TOKEN"
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-agent.service
journalctl -u nebula-agent.service -f
```

The unit declares `PartOf=nebula.service`, so `systemctl stop nebula` stops the agent
too, and `systemctl restart nebula-agent` does **not** restart Nebula (only the agent
itself).

### 3. Docker / sidecar

The agent ships in the same image as the server. A typical sidecar definition
shares `/etc/nebula` between `nebula` and the agent container:

```yaml
# docker-compose snippet
services:
  nebula:
    image: nebulaoss/nebula:latest
    volumes: [nebula-conf:/etc/nebula]
    network_mode: host
    cap_add: [NET_ADMIN]
  nebula-agent:
    image: ghcr.io/juev/nebula-mesh:latest
    entrypoint: ["/usr/local/bin/nebula-agent"]
    command: ["--config", "/etc/nebula-agent/agent.yml"]
    volumes:
      - nebula-conf:/etc/nebula
      - ./agent.yml:/etc/nebula-agent/agent.yml:ro

volumes:
  nebula-conf:
```

The PID file approach does not translate cleanly to containers; either run Nebula
under its own supervisor that watches `config.yml` for changes, or restart the
Nebula container when the agent rewrites configuration.

## Advanced per-host configuration

The host creation page (`/ui/hosts/new`) and the REST API (`POST /api/v1/hosts`)
support an optional **advanced** block for per-host overrides. The basic form
is unchanged; the advanced fields appear behind a collapsed *Advanced
configuration* details section in the UI and as a structured `advanced`
object in the API:

```jsonc
{
  "network_id": "…", "name": "edge-1", "nebula_ip": "10.0.0.1",
  "advanced": {
    "listen_host": "10.0.0.1",   // override default 0.0.0.0
    "mtu": 1300,                  // tun.mtu
    "tun_device": "nebula1",      // tun.dev
    "punchy": false,              // disable hole-punching for this host
    "unsafe_routes": [
      { "route": "192.168.10.0/24", "via": "10.0.0.99" }
    ]
  }
}
```

All advanced fields are optional. Omitted / empty fields inherit the network
default — render output for those hosts is byte-identical to a host with no
advanced block. Server-side validation rejects:

- `mtu` outside the 576–9216 range;
- non-IP `listen_host`;
- whitespace or slashes in `tun_device`;
- malformed CIDR or non-IP `via` in `unsafe_routes`.

## Configuration

The agent reads a YAML config file. The shipped template is
[`configs/agent.example.yml`](../configs/agent.example.yml):

```yaml
server_url: "https://mgmt.example.com:8080"   # management server base URL
data_dir: "/etc/nebula"                       # where host.crt/host.key/ca.crt/config.yml live
poll_interval: "30s"                          # how often to ask for updates
nebula_config_path: "/etc/nebula/config.yml"  # full path to the rendered nebula config
nebula_pid_file: "/run/nebula.pid"            # optional — if set, SIGHUP'd on changes
```

| Field | Default | Notes |
|---|---|---|
| `server_url` | (required) | Must be reachable from the host. HTTPS is strongly recommended. |
| `data_dir` | `/etc/nebula` | Owned by `root:root` 0700. Holds `host.key` (0600), `host.crt`, `ca.crt`, `config.yml`. |
| `poll_interval` | `30s` | Lower values reduce convergence time but increase server load. 5s–5m is the practical range. |
| `nebula_config_path` | `/etc/nebula/config.yml` | The agent overwrites this file atomically. |
| `nebula_pid_file` | (empty) | When set and the file holds a numeric PID, the agent sends `SIGHUP` after every successful write. |

## Enrollment

A host's first contact requires an **enrollment token** issued by the management
server. The token is single-use and short-lived (24h by default).

### 1. On the management server

Create the host record and grab its token via either the UI or the CLI:

```sh
nebula-mgmt host create \
  --server https://mgmt.example.com:8080 \
  --api-key "$API_KEY" \
  --network "$NETWORK_ID" \
  --name web-1 \
  --ip 192.168.100.10
# prints:
#   Host created: web-1 (ID: <uuid>)
#   Enrollment token: <token>
```

Capture the token — it is shown only once. If you lose it, the operator can rotate
it through `POST /api/v1/hosts/{id}/enrollment-token` (or via the UI).

### 2. On the host

```sh
# First run: enrolls, writes config to /etc/nebula-agent/agent.yml (0600),
# starts the poller. The token is single-use and is never written to disk.
sudo nebula-agent \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN"

# Optional: pick a non-default data dir on first run.
sudo nebula-agent --server ... --token ... --data-dir /etc/nebula
```

After a successful enrollment the agent writes the following to `data_dir`:

| File | Mode | Contents |
|---|---|---|
| `host.key` | 0600 | The host's Nebula private key (PEM, unencrypted). |
| `host.crt` | 0644 | The host's signed certificate. |
| `ca.crt`   | 0644 | The CA certificate; used by `nebula` to verify peers. |
| `config.yml` | 0644 | The rendered Nebula config. |
| `.fingerprint` | 0600 | The host's cert fingerprint; used by the agent to authenticate future updates. |

The enrollment endpoint accepts the token exactly once. A second call with the same
token returns `409 Conflict`.

### 3. Starting the run loop

Once the host has been enrolled, subsequent invocations need no arguments — the
agent reads `/etc/nebula-agent/agent.yml`, finds `host.crt`, and starts polling:

```sh
sudo nebula-agent                                # default config path
sudo nebula-agent --config /path/to/agent.yml    # non-default location
```

To change a setting later, edit the YAML file (preferred) or pass
`--update-config` together with the override flag to overwrite a single field
atomically:

```sh
sudo nebula-agent --update-config --poll-interval 60s
```

CLI overrides without `--update-config` are ignored on subsequent runs (a
warning is logged) so a one-shot flag never silently rewrites persisted state.

The agent exits non-zero if the host's certificate is missing and no `--token`
is supplied — the error message tells you to pass `--token TOK` to enroll.

### Legacy subcommands (deprecated)

The previous two-step ceremony still works for one release for backward
compatibility with existing scripts:

```sh
sudo nebula-agent enroll --server ... --token ... --data-dir /etc/nebula
sudo nebula-agent run --config /etc/nebula-agent/agent.yml
```

Both print a deprecation warning on stderr; switch to the unified form when
convenient.

## How updates work

Each `poll_interval` the agent:

1. Sends `GET /api/v1/agent/updates` with the host's certificate as a Bearer token.
2. The server replies with `304 Not Modified` if nothing changed (cheap), or the
   current `config.yml`, `host.crt`, and `ca.crt`.
3. Each file the server returned is written **atomically**: the agent writes to a
   sibling temp file with the same permissions, calls `fsync(2)`, then `rename(2)`s
   into place. A crash mid-write leaves either the old or the new file — never a
   half-written one.
4. If any file changed and `nebula_pid_file` is set, the agent reads the PID and
   sends `SIGHUP`, prompting Nebula to reload without dropping tunnels.

Certificate renewal is part of this same flow: when the server signs a new cert for
the host (e.g. because the previous one is within its 30-day expiry window), the
agent picks it up on the next poll.

### Lighthouse routing is automatic

Operators no longer wire lighthouse IPs into every peer host. The server resolves
the network's currently enrolled `role: lighthouse` hosts (excluding `pending`
and `blocked` ones) and embeds them in each peer's rendered `config.yml` under
`static_host_map` and `lighthouse.hosts`. When a lighthouse is added, blocked,
or deleted, the server bumps the network's `config_version`; each peer's next
agent poll observes the version change and receives an updated `config.yml` in
the same response — no manual reconfiguration required.

## Troubleshooting

### `dial tcp ...: connect: connection refused`

The host cannot reach the management server's `server_url`. Verify with
`curl -v <server_url>/healthz` from the host and check firewall / DNS.

### `401 unauthorized` after enroll

The host certificate is missing or doesn't match what the server expects. Check
that `data_dir/host.crt` exists and is readable, then try removing
`data_dir/.fingerprint` and re-running `enroll` (you'll need a fresh token).

### `cannot read certificate fingerprint`

`nebula-agent` was launched on a host with no `host.crt`. Pass `--token TOK`
to enroll, or check that `data_dir/host.crt` exists (the path in `agent.yml`).

### Nebula keeps using the old config

`nebula_pid_file` is empty or points at a non-existent PID. Either set it
correctly, or restart `nebula.service` manually after the agent updates the config.

### `permission denied: /etc/nebula/host.key`

The agent or Nebula are running as a non-root user without access to the data
directory. Either run them as root, or `chgrp` the directory to a shared group
(e.g. `nebula`) and set permissions to `0750` / files to `0640`.

### Tracing the agent

The agent logs to stderr; with systemd that means `journalctl -u nebula-agent`.
Increase verbosity by passing `--log-level debug` to `run`. Every successful poll
emits a `polling` line; every applied change emits an `applied` line listing the
affected files.

## Upgrading

1. Download the new release archive and `install -m 0755 nebula-agent /usr/local/bin/`.
2. `systemctl restart nebula-agent.service`.
3. Watch `journalctl -u nebula-agent -f` to confirm it polls successfully.

The agent is stateless apart from `data_dir`, so rolling upgrades are safe. The
file format under `data_dir` has been stable since v0.1.0.

## Removing or re-enrolling a host

### Remove from the server side

`nebula-mgmt host delete --id <host-id>` (or via the UI). The host's certificate
fingerprint is added to the blocklist, so the agent's next poll returns `401`.
Stop and remove `nebula-agent.service`, then delete `/etc/nebula` to clear secrets.

### Re-enroll the same host

Useful after the host's keys are believed compromised. On the server, `host
delete` the old record and create a new one; on the host:

```sh
sudo systemctl stop nebula-agent nebula
sudo rm /etc/nebula/{host.crt,host.key,ca.crt,config.yml,.fingerprint}
sudo nebula-agent --server <url> --token <new-token>
sudo systemctl start nebula nebula-agent
```

## Security notes

- **Key file permissions.** `host.key` is written with mode `0600`. Make sure the
  parent `data_dir` is not group- or world-readable.
- **TLS.** Set `server_url` to `https://…` in production. The agent uses the
  system trust store; if the management server uses a private CA, install the
  CA cert into the system trust store on every host.
- **Enrollment token handling.** Tokens are single-use and short-lived but should
  still be treated as secrets in transit. Prefer SSH or a configuration-management
  channel; never log them to disk.
- **Agent process privileges.** The supplied systemd unit runs as root because the
  default config writes to `/etc/nebula` and signals `nebula.service`. If you tighten
  this (group write + `CAP_KILL`), keep the `SystemCallFilter` and
  `ProtectSystem=strict` lines.
- **No outbound calls except to the management server.** The agent does not phone
  home anywhere else; you can lock its egress to that single endpoint in your
  firewall.
