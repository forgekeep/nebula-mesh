# Terraform module: `nebula-mgmt`

Stands up a single VM running `nebula-mgmt` from the official `.deb`
release. The module is cloud-agnostic at its boundary — pass in any
`instance` resource that exposes `public_ip` / `id` / a way to inject
`cloud-init` user-data — and ships a worked example for AWS EC2.

## What it does

1. Generates the bootstrap secrets:
   - `NEBULA_MGMT_MASTER_KEY` (random 32 bytes, base64-encoded).
   - `NEBULA_MGMT_CA_PASSPHRASE` (40-byte random string).
2. Materialises `server.yml` and a systemd drop-in from templates.
3. Builds a `cloud-init` user-data that installs the published `.deb`,
   stages the configs, runs `nebula-mgmt init` exactly once
   (idempotency guard: refuses to re-init if `data_dir/ca.crt` already
   exists), and enables `nebula-mgmt.service`.
4. Writes both secrets to the configured secret backend
   (`aws_secretsmanager` by default; swap via the `secret_backend`
   variable — see [SECRET_BACKENDS.md](SECRET_BACKENDS.md)).
5. Exposes outputs: `server_url`, `bootstrap_api_key`,
   `master_key_secret_arn`, `passphrase_secret_arn`.

The module **only** manages the management server. Use the
`nebula_agent` Ansible role to enrol hosts against it; agents need
nothing more than the server URL + a per-host enrolment token.

## Usage (AWS example)

```hcl
module "nebula_mgmt" {
  source = "github.com/forgekeep/nebula-mesh//deploy/terraform/nebula-mgmt?ref=v0.3.1"

  release_version = "v0.3.1"
  fqdn            = "mgmt.internal.example.com"
  tls_email       = "ops@example.com"   # for the Let's Encrypt issuer
  admin_username  = "admin"

  # Pass in the bare VM resource; the module never touches networking.
  instance_id          = aws_instance.nebula_mgmt.id
  instance_public_ip   = aws_instance.nebula_mgmt.public_ip
  ssh_user             = "ubuntu"

  secret_backend       = "aws_secretsmanager"
  aws_kms_key_id       = aws_kms_key.nebula.arn
}

output "nebula_mgmt_url" {
  value = module.nebula_mgmt.server_url
}
```

A complete example, including the `aws_instance` and security-group
plumbing, lives in [`examples/aws/`](examples/aws/).

## Idempotency

Re-running `terraform apply` is a no-op once the server is up:

- Secrets are created with `lifecycle { ignore_changes = [secret_string] }`
  so a re-run never rotates the CA passphrase / master key.
- The `cloud-init` script tests for `/var/lib/nebula-mgmt/ca.crt` before
  running `nebula-mgmt init`; presence ⇒ skip.
- Systemd unit is owned by the package; the module only ships a config
  drop-in under `/etc/systemd/system/nebula-mgmt.service.d/override.conf`,
  written with `cloud-init`'s built-in `manage_etc_hosts`-style merge so
  re-runs don't disturb local edits.

## Upgrading

Bump `release_version` and re-apply. The cloud-init script's
`runcmd` re-installs the package; systemd is restarted from the
deb post-install hook. The data directory (CA, DB, master key) is
preserved across upgrades — see the deb package contract in
[`deploy/packaging/`](../../packaging/).

## Variables

See [`variables.tf`](variables.tf) for the full list. Common knobs:

| Name | Default | Purpose |
|---|---|---|
| `release_version` | `latest` | Git tag of the release to install. |
| `fqdn` | (required) | DNS name the server will announce; used for TLS. |
| `tls_cert_path` / `tls_key_path` | `""` | Pre-staged cert/key. If empty, the server runs plain HTTP and the module **insists** on a reverse proxy. |
| `secret_backend` | `aws_secretsmanager` | One of `aws_secretsmanager`, `gcp_secret_manager`, `vault_kv`. |
| `admin_username` | `admin` | Seeded operator username. |
