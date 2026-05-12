# Ansible role: `nebula_agent`

Installs the per-host `nebula-agent` from the published `.deb` / `.rpm`,
writes `agent.yml`, runs `nebula-agent enroll` once (idempotent — guarded
by `data_dir/.fingerprint`), and enables `nebula-agent.service`.

The role does **not** mint enrolment tokens; pass each host its token via
a per-host variable (typically pulled from Ansible Vault or a secret
manager).

## Required variables

| Variable | Purpose |
|---|---|
| `nebula_agent_server_url` | Base URL of the management server. |
| `nebula_agent_enroll_token` | Per-host one-shot enrolment token. |

## Common optional variables

| Variable | Default | Purpose |
|---|---|---|
| `nebula_agent_release` | `latest` | Git tag to install. |
| `nebula_agent_data_dir` | `/etc/nebula` | Where host.crt/host.key/ca.crt/config.yml/.fingerprint live. |
| `nebula_agent_poll_interval` | `30s` | How often to ask the server for updates. |
| `nebula_agent_nebula_pid_file` | `/run/nebula.pid` | SIGHUP'd on changes (empty disables reload signal). |

See [`defaults/main.yml`](defaults/main.yml).
