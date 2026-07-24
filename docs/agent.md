# nebula-agent

The `nebula-agent` is the client-side counterpart to `nebula-mgmt`. It enrolls a host
into a network, polls the management server for configuration updates, writes Nebula's
`config.yml`, `host.crt`, `host.key`, and `ca.crt`, and signals `nebula` to pick up
managed updates.

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
- Write access to the parent directory of `signing_key_path` (`/etc/nebula-agent/` by default). For non-root deployments override this path to a directory the agent user owns.
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
curl -fsSL -O https://github.com/forgekeep/nebula-mesh/releases/download/<version>/nebula-agent_<version>_linux_amd64.deb
sudo apt install ./nebula-agent_<version>_linux_amd64.deb

# RHEL / Fedora / CentOS Stream / Rocky / Alma
sudo rpm -i https://github.com/forgekeep/nebula-mesh/releases/download/<version>/nebula-agent_<version>_linux_amd64.rpm
```

The package:

- installs `/usr/bin/nebula-agent` and `/lib/systemd/system/nebula-agent.service`;
- ships an example config at `/etc/nebula-agent/agent.example.yml`;
- creates the `nebula-agent` system user/group for future hardening;
- on fresh install runs `systemctl enable --now nebula-agent.service` so the daemon comes up immediately in **idle-standby** (#88) — no enrollment yet, no server traffic, journal logs one hint and the process sleeps;
- on upgrade leaves the current enable-state alone, and leaves `/etc/nebula-agent/agent.yml` and `/etc/nebula/{host.crt,host.key,ca.crt,config.yml}` untouched;
- on removal stops and disables the service but keeps `/etc/nebula-agent` and `/etc/nebula` intact (so host keys survive accidental removals). `apt purge` / `dnf remove --purge` will additionally delete the system user.

Bind the host with one command after install:

```sh
sudo nebula-agent enroll --server <url> --token <token>
```

The running daemon detects the freshly written files within ~10 seconds and transitions from idle-standby to the poll loop without a restart. See [Enrollment](#enrollment) for the full flow.

Checksums for every artifact are published in `checksums.txt` next to the package.

### 1b. From a release archive (other platforms)

For platforms without a native package (macOS, FreeBSD, Windows, Linux/arm v7),
replace `<version>` and `<platform>` as needed:

```sh
curl -fsSL -o nebula-agent.tar.gz \
  https://github.com/forgekeep/nebula-mesh/releases/download/<version>/nebula-agent_<platform>.tar.gz
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
sudo install -m 0600 /dev/stdin /run/nebula-enroll.token <<<"$ENROLL_TOKEN"
sudo nebula-agent --server https://mgmt.example.com:8080 --token-file /run/nebula-enroll.token
sudo rm /run/nebula-enroll.token
sudo systemctl daemon-reload
sudo systemctl enable --now nebula-agent.service
journalctl -u nebula-agent.service -f
```

The unit declares `PartOf=nebula.service`, so `systemctl stop nebula` stops the agent
too, and `systemctl restart nebula-agent` does **not** restart Nebula (only the agent
itself).

The supplied unit grants writes only below `/etc/nebula`. If an imported or
fresh installation keeps its config or PKI in another directory, add that
directory through a systemd drop-in; the agent does not edit the unit:

```ini
# sudo systemctl edit nebula-agent.service
[Service]
ReadWritePaths=/srv/nebula
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart
nebula-agent.service`. Include the parent directory of every configured
`nebula_config_path`, `nebula_ca_path`, `nebula_cert_path` and
`nebula_key_path`. The first managed config replacement also creates the
owner-only backup `<nebula_config_path>.pre-nebula-mesh.<import_session_id>` in
the config directory.

### 3. As a Windows service

The Windows archive contains the same `nebula-agent.exe` used interactively.
Run the following commands from an elevated PowerShell session. Install the
binary below `%ProgramFiles%` before registering the service: Windows runs it as
`LocalSystem`, so a binary replaceable by ordinary users would be a local
privilege-escalation path.

```powershell
$InstallDir = Join-Path $env:ProgramFiles 'Nebula Mesh'
$AgentRoot = Join-Path $env:ProgramData 'Nebula Mesh\Agent'
$NebulaRoot = Join-Path $env:ProgramData 'Nebula'
$AgentExe = Join-Path $InstallDir 'nebula-agent.exe'
$AgentConfig = Join-Path $AgentRoot 'agent.yml'

New-Item -ItemType Directory -Force $InstallDir, $AgentRoot, $NebulaRoot | Out-Null
Copy-Item .\nebula-agent.exe $AgentExe

# Remove inherited write access. SYSTEM and local Administrators retain full control.
icacls.exe $InstallDir /inheritance:r /grant:r `
  '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C
icacls.exe $AgentRoot /inheritance:r /grant:r `
  '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C
icacls.exe $NebulaRoot /inheritance:r /grant:r `
  '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C
```

Enroll the host with a one-time token file supplied through your deployment
system. Use the same config path that will be stored in the service definition,
then remove the token file:

```powershell
$TokenFile = Join-Path $AgentRoot 'enroll.token'
& $AgentExe enroll `
  --server https://mgmt.example.com:8080 `
  --token-file $TokenFile `
  --config $AgentConfig `
  --data-dir $NebulaRoot
Remove-Item $TokenFile
```

Register and start the service:

```powershell
& $AgentExe service install --config $AgentConfig
& $AgentExe service start
Get-Service NebulaMeshAgent
```

`install` records an automatic-start `NebulaMeshAgent` service running as
`LocalSystem`. Fatal exits are restarted after five seconds. You may also
install before enrollment: the service stays in idle-standby and detects the
new config and keys within about ten seconds after `enroll` completes.

Agent logs are written to the Windows Application Event Log:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Application'
  ProviderName = 'NebulaMeshAgent'
} -MaxEvents 20
```

Control or remove the service with:

```powershell
& $AgentExe service restart
& $AgentExe service stop
& $AgentExe service uninstall
```

Uninstalling the service does not delete `agent.yml`, certificates, or private
keys. Windows cannot use the Unix `SIGHUP` mechanism, so leave
`nebula_pid_file` empty and restart the separate Nebula service after managed
config updates when required.

### 4. Docker / sidecar

The agent is published as its own image, `ghcr.io/forgekeep/nebula-agent`
(the server ships separately as `ghcr.io/forgekeep/nebula-mgmt`). The agent
image already runs `run --config /etc/nebula-agent/agent.yml` by default, so a
sidecar just shares `/etc/nebula` between `nebula` and the agent container:

```yaml
# docker-compose snippet
services:
  nebula:
    image: nebulaoss/nebula:latest
    volumes: [nebula-conf:/etc/nebula]
    network_mode: host
    cap_add: [NET_ADMIN]
  nebula-agent:
    image: ghcr.io/forgekeep/nebula-agent:latest
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
  "network_id": "…", "name": "edge-1", "nebula_ips": ["10.0.0.1"],
  "advanced": {
    "listen_host": "10.0.0.1",   // override default 0.0.0.0
    "mtu": 1300,                  // tun.mtu
    "tun_device": "nebula1",      // tun.dev
    "punchy": false,              // disable hole-punching for this host
    "unsafe_routes": [
      { "route": "192.168.10.0/24", "via": "10.0.0.99" }
    ],
    "firewall_inbound": [
      { "port": "22", "proto": "tcp", "group": "admin" }
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
- malformed CIDR or non-IP `via` in `unsafe_routes`;
- `firewall_inbound` rules with a proto outside `any`/`tcp`/`udp`/`icmp`, a
  port that is not `any`, a single port `1-65535` or an ascending range
  `a-b`, an empty or overlong (>64 chars) group, or more than 64 rules.

### Per-host inbound firewall rules

`advanced.firewall_inbound` appends host-specific inbound rules **after** the
network-wide firewall policy in the rendered `config.yml` — additive only,
inbound only; the network policy and the outbound section are never modified.
In the UI the rules are entered one per line as `PORT/PROTO from GROUP`
(e.g. `443/tcp from web`, `8000-9000/udp from monitoring`). A rule with group
`any` renders as `host: any` (matches every peer), same as the network
policy. Changing these rules re-publishes only the affected host's config on
its next poll. Mobile bundles include them too. Note that mesh import always
captures firewall policy at network level — per-host rules are never derived
from imported configs.

### Multiple overlay addresses per host

As of version 0.3.0, hosts can be assigned multiple overlay addresses from a network's
CIDR prefixes. This enables:

- **Dual-stack networks** — assign both IPv4 and IPv6 addresses to the same host.
- **Segmented address plans** — assign hosts from multiple subnets within the same Nebula network.

The `nebula_ips` field contains the ordered list of addresses:

```jsonc
{
  "name": "dual-stack-host",
  "nebula_ips": ["10.42.0.10", "fd00:42::10"],
  "network_id": "…"
}
```

When a host is created with multiple addresses, the issued certificate contains all prefixes
in the declared order. The configuration generated for the host includes all addresses in
`static_host_map` (one entry per address for each lighthouse) and `lighthouse.hosts` (all
addresses of all lighthouses). Reordering the `nebula_ips` list will trigger a new certificate
issuance on the next agent poll.

**API Note:** The legacy singular fields (`nebula_ip`, `cidr`) were removed in v0.3.0. If you
are migrating from an earlier version, replace:
- `"nebula_ip": "10.42.0.10"` → `"nebula_ips": ["10.42.0.10"]`
- `"cidr": "10.42.0.0/24"` → `"cidrs": ["10.42.0.0/24"]`

## Configuration

The agent reads a YAML config file. The shipped template is
[`configs/agent.example.yml`](../configs/agent.example.yml):

```yaml
server_url: "https://mgmt.example.com:8080"   # management server base URL
data_dir: "/etc/nebula"                       # where host.crt/host.key/ca.crt/config.yml live
poll_interval: "30s"                          # how often to ask for updates
nebula_config_path: "/etc/nebula/config.yml"  # full path to the rendered nebula config
nebula_pid_file: "/run/nebula.pid"            # optional — if set, SIGHUP'd on changes
signing_key_path: "/etc/nebula-agent/host.signing.key"  # Ed25519 PoP signing key — parent dir must be writable by the agent user
```

| Field | Default | Notes |
|---|---|---|
| `server_url` | (required) | Must be reachable from the host. Must be `https://` unless the host is loopback — a plaintext `http://` URL on any other host is refused at startup because the enrollment token and rendered Nebula config would transit in cleartext. |
| `data_dir` | `/etc/nebula` | Owned by `root:root` 0700. Holds `host.key` (0600), `host.crt`, `ca.crt`, `config.yml`. |
| `poll_interval` | `30s` | Lower values reduce convergence time but increase server load. 5s–5m is the practical range. |
| `nebula_config_path` | `/etc/nebula/config.yml` | The agent overwrites this file atomically. |
| `nebula_pid_file` | (empty) | When set and the file holds a numeric PID, the agent sends `SIGHUP` after every successful write. |
| `signing_key_path` | `/etc/nebula-agent/host.signing.key` | Ed25519 PoP signing key (ADR 0004). Override for non-root setups so the parent directory is writable by the agent user. |
| `allow_insecure_http` | `false` | Opts out of the `https`-required guard on `server_url` (or pass `--insecure-http`). Only for isolated lab networks; credentials transit in the clear. |

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

After `apt install` / `dnf install`, `nebula-agent.service` is already running in **idle-standby** (#88) — confirm via `systemctl status nebula-agent`. Bind the host with one command:

```sh
sudo nebula-agent enroll \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN"
```

The `enroll` subcommand:

- generates both keypairs (X25519 for Nebula + Ed25519 for poll signatures);
- hits `POST /api/v1/enroll` on the server;
- writes `agent.yml` atomically (mode 0600) and writes each enrollment file to its
  configured path after checking every destination directory;
- runs **one** confirmation signed poll so you see `enrollment successful (confirmation poll OK)` in the same command;
- exits 0.

The token is single-use and never persisted to disk. Pass `--force` to overwrite an existing enrollment (e.g. after key compromise) — without `--force` the command refuses to clobber `host.crt` / `agent.yml`.

To write the rendered Nebula config somewhere other than `<data-dir>/config.yml` (e.g. when Nebula reads its config from a custom path), pass `--nebula-config-path`. The value is recorded as `nebula_config_path` in `agent.yml`, and both the initial enrollment and the running daemon write the config there.

After a successful enrollment the agent owns the following files:

| Path | Mode | Owner | Contents |
|---|---|---|---|
| `/etc/nebula-agent/agent.yml` | 0600 | agent | Agent daemon config (server URL, poll interval, paths). |
| `/etc/nebula-agent/host.signing.key` | 0600 | **agent** | Ed25519 private key used only by the agent to sign poll requests (ADR 0004). Lives outside `/etc/nebula/` because Nebula does not read it. |
| `/etc/nebula/host.key` | 0600 | Nebula | X25519 private key for the Nebula Noise handshake. |
| `/etc/nebula/host.crt` | 0644 | Nebula | Signed certificate of this host. |
| `/etc/nebula/ca.crt` | 0644 | Nebula | CA certificate (trust anchor for peer-cert verification). |
| `/etc/nebula/config.yml` | 0644 | Nebula | Rendered Nebula config (lighthouses, firewall, …). |

The running daemon detects all four required files (`agent.yml`, `host.crt`, `host.signing.key`) within ~10 s and transitions from idle-standby to the poll loop without a restart.

### 3. Containers / non-systemd setups

For Docker and other systemd-less environments where there is no idle daemon to wait, the legacy one-shot flow still works:

```sh
sudo nebula-agent \
  --server https://mgmt.example.com:8080 \
  --token "$ENROLL_TOKEN"
```

That invocation enrolls and **then** starts the poll loop in the foreground. Use it as the container's main process (`ENTRYPOINT`).

CLI overrides for the running daemon (e.g. `--poll-interval 60s`) take effect only with `--update-config`; otherwise a warning is logged and the on-disk file wins:

```sh
sudo nebula-agent --update-config --poll-interval 60s
```

### Legacy subcommands (deprecated)

`nebula-agent run` is a deprecated alias for `nebula-agent` without a subcommand:

```sh
sudo nebula-agent run --config /etc/nebula-agent/agent.yml
```

It prints a deprecation warning on stderr; switch to the unified form when
convenient.

## Import an existing mesh

Use a mesh import when Nebula already runs on the hosts and you want the server
to adopt its CA, certificates, routes, lighthouses, relays, firewall and
blocklist.

### 1. Import the existing CA

Open `/ui/cas/import`, or run:

```sh
nebula-mgmt ca import \
  --server https://mgmt.example.com:8080 \
  --api-key "$API_KEY" \
  --name production-existing \
  --cert-file /secure/ca.crt \
  --key-file /secure/ca.key
```

For an encrypted CA key, add `--passphrase-file /secure/ca.passphrase`. The CLI
decrypts the key locally and never puts the passphrase in argv or the request.
The server requires HTTPS, except for a literal loopback HTTP URL.

Create an empty Network bound to the imported CA. The server rejects a Network
that already has hosts, shares its CA with another Network, has a CA-scoped
blocklist, or uses a retired CA or a CA with an active successor.

### 2. Start collection

Open `/ui/mesh-imports/new`, select the Network and CA, and set the expected host
count when you know it. The server shows an `nmi_` import token once. This token
can register several hosts in that session until it expires, reaches the
configured host count, or an operator cancels or finalizes the session.

The import token only authorizes registration. After registration, the agent
uses its Ed25519 signing key for polls and config acknowledgements. You do not
need to reauthorize it with an enrollment token.

### 3. Run the agent on each existing host

Put the token in an owner-controlled file and point the agent at the config that
the running Nebula daemon uses:

```sh
sudo nebula-agent enroll \
  --server https://mgmt.example.com:8080 \
  --token-file /run/secrets/nebula-import-token \
  --nebula-config-path /etc/nebula/config.yml
```

The first run reads the effective config and prints the discovered files. It
stops before contacting the server. Review the manifest, then confirm the same
discovery:

```sh
sudo nebula-agent enroll \
  --server https://mgmt.example.com:8080 \
  --token-file /run/secrets/nebula-import-token \
  --nebula-config-path /etc/nebula/config.yml \
  --yes
```

The agent accepts a complete file-backed installation with clean absolute paths
for `pki.ca`, `pki.cert` and `pki.key`. It verifies the host key against the
certificate and the certificate against the imported CA. A partial install,
inline PKI or a mismatched key stops before a network request.

Compatibility is intentionally narrow for the first adoption flow:

| Existing installation | Import behavior |
|---|---|
| One Curve25519 CA certificate and one X25519 host certificate/key in regular files | Supported |
| `static_host_map`, `lighthouse`, `relay`, and `lighthouse+relay` roles, `listen`, `punchy`, `tun`, `unsafe_routes`, firewall and CA blocklist | Imported and reconciled |
| Logging, stats and SSH daemon settings | Reported as warnings; server does not manage them |
| Other unsupported connectivity settings | Blocking preview issue |
| P256 CA, host certificate or private key | Rejected before registration |
| Inline PEM in `pki.ca`, `pki.cert` or `pki.key`, or `pkcs11:` keys | Rejected before registration |
| Directory/fragment-based Nebula configuration | Rejected; point `--nebula-config-path` at one effective file |
| Multiple CA roots in `pki.ca` | Rejected; import requires one exact current root |

Registration uploads a sanitized snapshot. The agent does not upload private
keys or arbitrary YAML values. It preserves the existing CA, certificate, key
and config files while the session has status `collecting`; signed polls return
`import_pending` without writing those files.

### 4. Review and finalize

The session page shows a normalized Host proposal with source snapshot IDs and
the status each Host will receive.
Resolve blockers such as missing lighthouse or relay endpoints, divergent
firewalls, divergent blocklists and unsupported connectivity settings.
Warnings for certificate expiry or optional settings require a checkbox
acknowledgement.

Finalize after the displayed count matches `expected_hosts`, when set, and you
have confirmed the inventory checkbox. The server rejects a stale revision or
any Network, CA, Host-set or blocklist change since collection began. A
successful finalize commits roles, endpoints, advanced settings, firewall and
blocklist in one transaction. Hosts whose certificate fingerprints appear in
the imported blocklist remain `blocked`; other Hosts become `enrolled`. A
matching blocklist row links to its blocked Host. Finalize also increments the
Network config version.

The next poll validates and writes the server-rendered config. Before replacing
an imported config, the agent creates an owner-only backup named
`<nebula_config_path>.pre-nebula-mesh.<import_session_id>`. It keeps the imported
certificate and key paths from the discovery profile. Certificate renewal then
uses the managed lifecycle.

A blocked imported agent receives `403 revoked` after finalize. Unblock it only
when you intend to authorize its existing identity again. Unblock deletes the
old certificate fingerprint from the CA blocklist and changes the Host to
`pending`; the server accepts the old Ed25519 signing key immediately. Every
Network using that CA receives a config version bump, so peers accept the old
Nebula certificate after they poll and apply the new blocklist. Run a separate
re-enrollment or force-rotate operation if you need new credentials. Unblock
does not provide an atomic credential replacement.

The REST workflow uses these protected endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/mesh-imports` | Start collection and return the import token once. |
| `GET /api/v1/mesh-imports/{id}` | Read the current revision, blockers, warnings and normalized proposal. |
| `POST /api/v1/mesh-imports/{id}/rotate-token` | Replace the reusable import token. |
| `POST /api/v1/mesh-imports/{id}/cancel` | Cancel collection and remove its temporary importing hosts. |
| `POST /api/v1/mesh-imports/{id}/finalize` | Commit the acknowledged current proposal. |

### Token selection, retries and rollback

The operation chooses the token type; the UI has no generic token selector.
`Add Host` and re-enrollment issue single-host `nme_` enrollment tokens.
`Import existing mesh` and session token rotation issue reusable, session-bound
`nmi_` tokens. The agent checks local state and the prefix before network I/O:
an `nmi_` token without a complete existing installation is rejected, while an
`nme_` token on an existing installation requires explicit destructive
`--force`.

Retry `nebula-agent enroll ... --yes` with the same `nmi_` token and signing-key
path after a timeout. Registration is idempotent only for the same host
certificate and Ed25519 signing key. A prefix/state mismatch, expired or rotated
token, different signing key, duplicate overlay address, or completed session
returns an error instead of creating another identity.

The agent retries the final proof request once only when its accepted response
cannot be decoded or a transport error makes the outcome ambiguous. It reuses
the exact request bytes. An explicit response is never recovered through a poll:
`409 import_challenge_used` is recoverable only on that retry, while
`422 import_payload_conflict` and `409 agent_import_conflict` are errors.

The server allows two outstanding proof challenges per host certificate. A
`429 Too Many Requests` response leaves both existing challenges valid; wait
for the `Retry-After` interval and run the same command again. The session also
limits simultaneous outstanding challenges to twice `expected_hosts`, bounded
to 2–4096, or 4096 when the expected count is unknown. Start larger fleets in
waves; each successful registration frees capacity. Rotating the import token
invalidates all challenges issued for the previous token.

Before finalize, use Cancel in the session page or
`POST /api/v1/mesh-imports/{id}/cancel`. Cancellation removes temporary
`importing` hosts and records tombstones; it does not touch Nebula files. Start a
new session to retry. After finalize there is no conversion back to
`collecting`: stop the agents, restore each
`<nebula_config_path>.pre-nebula-mesh.<import_session_id>` if connectivity was
lost, and either fix the managed topology or restore the server database from a
pre-finalize backup. Never replace `host.key` during this rollback.

## Agent authorization (ADR 0004)

Every poll request the agent sends to the management server is cryptographically
signed with a per-host Ed25519 keypair that is generated at enrollment time and
bound to the host row server-side. The fingerprint of `host.crt` identifies the
host; the signature proves the agent still holds the matching private key. See
[`docs/adr/0004-agent-authorization.md`](adr/0004-agent-authorization.md) for the
decision history.

### Keys on disk

After a successful enrollment two private keys exist on the host, both mode `0600`. They live in **separate directories** because they belong to separate processes (#88):

| Path | Owner | Purpose |
|---|---|---|
| `/etc/nebula/host.key` | Nebula | X25519 private key used by Nebula for the Noise handshake between peers. |
| `/etc/nebula-agent/host.signing.key` | agent | Ed25519 private key used only by the agent to sign poll requests. Never seen by Nebula. |

The two keys share lifetime — force-rotate and re-enroll regenerate both together. The Ed25519 key exists because X25519 (the curve of `host.crt`) is a DH scheme that cannot sign arbitrary messages.

### Headers on every poll

Every `GET /api/v1/agent/updates` and config acknowledgement carries four headers:

| Header | Value |
|---|---|
| `X-Nebula-Fingerprint` | `cert.Fingerprint(host.crt)` (SHA-256 of the cert PEM). |
| `X-Nebula-Timestamp` | RFC3339 UTC, e.g. `2026-05-13T08:30:00Z`. |
| `X-Nebula-Nonce` | 16 random bytes, base64-encoded. |
| `X-Nebula-Signature` | Ed25519 signature, base64-encoded, over the canonical string below. |

The canonical string is:

```
METHOD || "\n" || PATH || "\n" || HOST_HEADER || "\n" || TIMESTAMP || "\n" || NONCE
```

The server enforces:

- All four headers present. Missing → `400 missing_signature`.
- Fingerprint resolves to a live host row, or its `prev_cert_fingerprint`
  during a rotation overlap window. Otherwise → `401 unknown_fingerprint`.
  If the fingerprint is on the blocklist (host was deleted), the server
  returns `410 gone` instead (see below).
- Signature verifies against `host.signing_pub_pem` stored at enrollment.
  Otherwise → `401 bad_signature`.
- Timestamp within ±5 minutes of server time. Otherwise → `401 timestamp_skew`.
- `(host_id, nonce)` not seen in the last 10 minutes by this server process.
  Otherwise → `401 replayed_nonce`.

Every failure path writes a `host.auth.failed` audit entry with a structured
`details` field containing the reason code.

Clock skew is a real operational concern. Run `chronyd` / `systemd-timesyncd` on
every host; the ±5 min window will absorb routine drift but not an unset RTC.

### Revocation signals

- **`403 revoked`** — the host's status is `blocked` (e.g. the operator clicked
  *Block* in the UI). Response body:

  ```json
  {"reason": "revoked", "message": "...", "blocked_at": "2026-05-13T08:30:00Z"}
  ```

- **`410 gone`** — the host row no longer exists but its fingerprint still
  appears in the blocklist (the row was deleted server-side). Response body:

  ```json
  {"reason": "gone", "message": "...", "deleted_at": "2026-05-13T08:30:00Z"}
  ```

In both cases the agent logs at ERROR, stops the poll loop, and exits with
status 0 so systemd does **not** auto-restart it into the same denied state.
To re-attach the host: create a new host record on the server (or use
`/api/v1/hosts/{id}/reenroll`) and run `nebula-agent --token <fresh>` once.

### Cert rotation overlap window

When the server auto-renews a host certificate inside `handleAgentUpdates`,
the previous fingerprint is parked in `hosts.prev_cert_fingerprint`. The
poll handler accepts either fingerprint for ~2 × `poll_interval` so the
race between the server-side cert update and the agent's atomic on-disk
write does not lock the agent out. The slot clears as soon as the agent
comes back with the new fingerprint, or after the wall-clock window
expires — whichever happens first.

### Operator endpoints

| Endpoint | Effect |
|---|---|
| `POST /api/v1/hosts/{id}/enrollment-token` | Mints a fresh single-use enrollment token bound to the existing host row. Previous active tokens are invalidated. Audit: `host.reenroll.requested` with `details=regenerate-token: <name>`. |
| `POST /api/v1/hosts/{id}/reenroll` | Same mechanics as the previous endpoint; exposed as a discrete route so UIs can present "re-enroll" (lost keys) as a distinct intent. Audit: `host.reenroll.requested` with `details=reenroll: <name>`. |
| `POST /api/v1/hosts/{id}/rotate-cert?new_key=false` | Re-signs the existing public key immediately. Returns the new cert + CA in the response body. Audit: `host.rotate-cert.requested` with `details=new_key=false`. |
| `POST /api/v1/hosts/{id}/rotate-cert?new_key=true` | Sets `pending_rekey` on the host row. The next poll response carries `rekey_required: true` plus a single-use `enrollment_token`; the agent regenerates both keypairs and re-enrolls. A second concurrent call answers `409`. Audit: `host.rotate-cert.requested` with `details=new_key=true`. |

`enrollment_token.ttl` is configurable: a per-network override sits in
`network_config["enrollment_token_ttl"]`; the server-wide default lives in
`enrollment_token_ttl` in `server.yml` (default `24h`).

### Audit reason codes

`host.auth.failed` entries carry one of the following reason codes in the
`details` column. The Web UI's audit log renders them as discrete labels.

| Reason | Cause |
|---|---|
| `unknown_fingerprint` | Fingerprint not bound to any live host row (and not blocklisted). |
| `bad_signature` | Headers missing, signature failed Ed25519 verify, or signing key absent. |
| `timestamp_skew` | RFC3339 timestamp outside ±5 minutes. |
| `replayed_nonce` | Duplicate `(host_id, nonce)` observed inside the idle window. |
| `revoked` | Host is in `blocked` state — 403 was returned. |
| `gone` | Host row deleted; fingerprint still in the blocklist — 410 was returned. |

## How updates work

Each `poll_interval` the agent:

1. Sends `GET /api/v1/agent/updates` with the four `X-Nebula-*` PoP headers
   described in [Agent authorization](#agent-authorization-adr-0004). The
   server verifies the signature and the timestamp / nonce before answering.
2. The server replies with `304 Not Modified` if nothing changed (cheap), or the
   current `config.yml`, `host.crt`, and `ca.crt`.
3. Each file the server returned is written **atomically**: the agent writes to a
   sibling temp file with the same permissions, calls `fsync(2)`, then `rename(2)`s
   into place. A crash mid-write leaves either the old or the new file — never a
   half-written one.
4. If any file changed and `nebula_pid_file` is set, the agent reads the PID and
   sends `SIGHUP`, prompting Nebula to reload without dropping tunnels.
5. For agents advertising `config_ack_v1`, the server keeps the delivered
   `config_version` pending. After validation, atomic write, and successful
   `SIGHUP` delivery, the agent sends a signed
   `POST /api/v1/agent/config-ack/<version>`. Without `nebula_pid_file`, the ack
   means only that the config was validated and written. It does not prove that
   Nebula accepted the reload or that the tunnel is healthy. Until the ack is
   committed, later polls receive the newest config again; duplicate ack
   requests are idempotent when signed with a fresh nonce.

Certificate renewal is part of this same flow: when the server signs a new cert for
the host (e.g. because the previous one is within its 30-day expiry window), the
agent picks it up on the next poll.

### Lighthouse and relay routing is automatic

Operators no longer wire lighthouse IPs into every peer host. The server resolves
the network's currently enrolled `role: lighthouse` hosts (excluding `pending`
and `blocked` ones) and embeds them in each peer's rendered `config.yml` under
`static_host_map` and `lighthouse.hosts`. When a lighthouse is added, blocked,
or deleted, the server bumps the network's `config_version`; each peer's next
agent poll observes the version change and receives an updated `config.yml` in
the same response — no manual reconfiguration required.

The server resolves enrolled `role: relay` hosts and writes their overlay
addresses to `relay.relays`. It excludes pending, importing and blocked relays.

Use `role: lighthouse+relay` when one Nebula instance should perform both
duties. The server enables `lighthouse.am_lighthouse` and `relay.am_relay` in
that host's config, and advertises the host to peers as both a lighthouse and a
relay. Like the individual infrastructure roles, the combined role requires
`public_ip` and `listen_port`.

The OpenAPI `Host.role` and `CreateHostRequest.role` enums now include
`lighthouse+relay`. JSON clients that treat `role` as an arbitrary string
remain compatible. Clients generated with a closed enum, or clients with
exhaustive switches over the previous values, must add the new value before
creating or decoding combined-role hosts.

## Troubleshooting

### `dial tcp ...: connect: connection refused`

The host cannot reach the management server's `server_url`. Verify with
`curl -v <server_url>/healthz` from the host and check firewall / DNS.

### `401 unauthorized` after enroll

Read the `error` field of the response — it carries one of the structured
reason codes (`bad_signature`, `unknown_fingerprint`, `timestamp_skew`,
`replayed_nonce`). The matching `host.auth.failed` audit entry on the server
spells out which check failed. Common causes:

- `timestamp_skew` — host clock is wrong; install `chronyd` or
  `systemd-timesyncd`.
- `bad_signature` — `host.signing.key` was rotated out from under the agent
  (e.g. someone copied an old `data_dir` over the new one). Re-enroll.
- `unknown_fingerprint` — `host.crt` no longer matches any host row.
  Re-enroll the host (see [Re-enroll the same host](#re-enroll-the-same-host)).

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
fingerprint is added to the blocklist, so the agent's next poll returns
`410 gone`.
Stop and remove `nebula-agent.service`, then delete `/etc/nebula` to clear secrets.

### Re-enroll the same host

Useful after the host's keys are believed compromised. Two flavours:

1. **Preserve the host row** (recommended — keeps the IP allocation, group
   membership, audit history). On the server:

   ```sh
   curl -X POST -H "Authorization: Bearer $API_KEY" \
     https://mgmt.example.com:8080/api/v1/hosts/<host-id>/reenroll
   # returns {"token": "...", "expires_at": "..."}
   ```

   On the host:

   ```sh
   sudo rm /etc/nebula/{host.crt,host.key,ca.crt,config.yml} \
           /etc/nebula-agent/host.signing.key /etc/nebula-agent/agent.yml
   sudo nebula-agent enroll --server <url> --token <new-token>
   ```

   The running daemon (still in poll loop or already in idle-standby after
   the deletions) picks up the new artefacts within ~10 s.

2. **Server-driven force-rotate** (no operator action on the host). On the
   server:

   ```sh
   curl -X POST -H "Authorization: Bearer $API_KEY" \
     "https://mgmt.example.com:8080/api/v1/hosts/<host-id>/rotate-cert?new_key=true"
   ```

   The next poll response carries `rekey_required: true` plus a fresh token.
   The agent generates both keypairs, calls `/api/v1/enroll`, and writes the
   CA, certificate, key and config to the paths in its current AgentProfile.
   Imported custom paths stay in place; rekey does not migrate them into
   `data_dir`. The agent checks every destination directory before consuming
   the single-use token, then writes the files individually.

   When `nebula_pid_file` is configured, the agent sends `SIGHUP` after all
   writes and before acknowledging the config version. A signal error leaves
   the version pending; the next signed poll returns the current config again.
   With no PID file, management re-enrollment and acknowledgement complete, and
   you must restart Nebula to load the new identity.

3. **Hard reset** (last resort, churns the host row). `host delete` the
   old record on the server and create a new one; agent steps as in
   option 1.

## Security notes

- **Key file permissions.** Both `host.key` and `host.signing.key` are written
  with mode `0600`. Make sure the parent `data_dir` is not group- or
  world-readable. Leaking `host.signing.key` lets an attacker poll on behalf
  of the host until the operator either blocks it (`/block`) or force-rotates
  it (`/rotate-cert?new_key=true`).
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
