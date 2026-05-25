# Deployment recipes

Three opinionated paths cover the common ways operators stand up a
production `nebula-mgmt` + agent fleet. Pick the one that matches your
infra; mix-and-match is fine (e.g. Terraform for the server, Ansible for
the agents).

| Path | Use when |
|---|---|
| [Terraform module](#terraform) | You provision VMs through Terraform and want the server brought up from scratch in one apply. Ideal for AWS / GCP / libvirt where the secret store lives next door. |
| [Ansible roles](#ansible) | You already have an Ansible inventory and prefer configuration-management over hand-rolled cloud-init. Idempotent, runs against existing VMs. |
| [Cloud-init snippets](#cloud-init) | One-off VMs or hand-managed servers where neither Terraform nor Ansible is in play. Paste into your provider's user-data field. |

All three share the same secret-handling contract: **`NEBULA_MGMT_MASTER_KEY`
and `NEBULA_MGMT_CA_PASSPHRASE` are generated once and stored in a secret
manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, or
Ansible Vault). Re-running the recipe must never rotate either secret —
the CA passphrase is load-bearing for every previously-issued
certificate.** Idempotency in the recipes is implemented by guarding on
the presence of `data_dir/ca.crt`.

## Terraform

Path: [`deploy/terraform/nebula-mgmt/`](../deploy/terraform/nebula-mgmt/).
Cloud-agnostic at its boundary; ships a worked AWS example with
`aws_secretsmanager_secret` resources backing the bootstrap secrets.

Quickstart:

```hcl
module "nebula_mgmt" {
  source              = "github.com/forgekeep/nebula-mesh//deploy/terraform/nebula-mgmt?ref=v0.3.5"
  release_version     = "v0.3.5"
  fqdn                = "mgmt.internal.example.com"
  instance_id         = aws_instance.nebula_mgmt.id
  instance_public_ip  = aws_instance.nebula_mgmt.public_ip
  secret_backend      = "aws_secretsmanager"
  aws_kms_key_id      = aws_kms_key.nebula.arn
}
```

Read the full variable list and the secret-backend swap instructions in
the [module README](../deploy/terraform/nebula-mgmt/README.md).

## Ansible

Path: [`deploy/ansible/roles/`](../deploy/ansible/roles/) — two roles,
`nebula_mgmt` and `nebula_agent`. A complete playbook lives in
[`deploy/ansible/examples/site.yml`](../deploy/ansible/examples/site.yml).

```sh
ansible-playbook -i inventory.example.ini site.yml --ask-vault-pass
```

Tested against Ubuntu 22.04 / 24.04, Debian 12, Rocky / Alma Linux 9.
The roles always pull the published `.deb` / `.rpm` artifacts; they
never compile from source on the target hosts. Both roles are
idempotent — re-running is a no-op once the install + enrol have
succeeded.

## Cloud-init

Path: [`deploy/cloud-init/`](../deploy/cloud-init/). Two examples,
`nebula-mgmt.example.yaml` and `nebula-agent.example.yaml`. Paste into
your provider's user-data field after replacing the `<...>`
placeholders. The script installs the package, materialises the config,
runs `init` / `enroll` exactly once, and enables the systemd unit.

## Upgrades

All three paths use the published `.deb` / `.rpm` artifacts, so an
upgrade is "bump the release tag and re-apply":

- Terraform: change `release_version`, `terraform apply`.
- Ansible: change `nebula_mgmt_release` / `nebula_agent_release`,
  re-run the playbook.
- Cloud-init: change the `version` in `runcmd` and re-apply the
  user-data (cloud-init only runs once per VM by default — most
  operators upgrade in-place via the package manager instead).

The package contract preserves `data_dir` and `/etc/nebula-mgmt/` /
`/etc/nebula-agent/` across upgrades.

## You should run TLS

The roles and the cloud-init snippets default to plain HTTP because TLS
material is operator-specific. **Always front the management server
with a TLS-terminating proxy (nginx, Caddy, Traefik) or set
`tls_cert` / `tls_key` directly in the server config.** Agents talk to
the server over the public internet during enrolment; plain HTTP leaks
the enrolment token and the rendered Nebula config (including the
freshly-signed certificate) to anyone on-path.
