# Ansible role: `nebula_mgmt`

Installs and configures the management server (`nebula-mgmt`) on a Linux
host using the published `.deb` / `.rpm` packages. Idempotent: the role
never re-runs `nebula-mgmt init` after the first successful bootstrap
(guarded by the presence of `data_dir/ca.crt`).

## Tested against

- Ubuntu 22.04 / 24.04
- Debian 12
- Rocky Linux 9 / Alma Linux 9

## Required variables

| Variable | Purpose |
|---|---|
| `nebula_mgmt_release` | Git tag of the release to install (e.g. `v0.3.1` or `latest`). |
| `nebula_mgmt_master_key` | Base-64 32-byte AES-256 master key. Pull from Vault. |
| `nebula_mgmt_ca_passphrase` | Legacy single-CA passphrase. Pull from Vault. |

## Common optional variables

| Variable | Default | Purpose |
|---|---|---|
| `nebula_mgmt_listen` | `":8080"` | Bind address. |
| `nebula_mgmt_data_dir` | `/var/lib/nebula-mgmt` | DB + CA storage. |
| `nebula_mgmt_log_level` | `info` | One of debug/info/warn/error. |
| `nebula_mgmt_tls_cert` / `..._key` | unset | Path on the target host. |
| `nebula_mgmt_metrics_prometheus` | `true` | Toggle `/metrics`. |
| `nebula_mgmt_alerts_enabled` | `false` | Cert-expiry alerter (issue #41). |
| `nebula_mgmt_admin_username` | `admin` | Seed operator username. |

See [`defaults/main.yml`](defaults/main.yml) for the full list.

## Example play

```yaml
- hosts: nebula_mgmt
  become: true
  roles:
    - role: nebula_mgmt
      vars:
        nebula_mgmt_release: "v0.3.1"
        nebula_mgmt_master_key: "{{ lookup('community.hashi_vault.vault_read',
                                        'secret/nebula/master_key').value }}"
        nebula_mgmt_ca_passphrase: "{{ lookup('community.hashi_vault.vault_read',
                                        'secret/nebula/ca_passphrase').value }}"
```

A complete sample lives in [`../../examples/site.yml`](../../examples/site.yml).
