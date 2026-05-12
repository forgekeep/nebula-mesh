terraform {
  required_version = ">= 1.5"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = []
    }
  }
}

# --- Bootstrap secrets ---------------------------------------------------
#
# Both secrets are generated once and pinned. The `lifecycle` block on the
# secret-store resource keeps the value stable across Terraform applies so a
# routine `terraform apply` cannot accidentally rotate the CA passphrase
# (which would brick every previously-issued certificate).
#
# Use `terraform taint` or an out-of-band CLI flow if you ever genuinely need
# to rotate either secret.

resource "random_password" "ca_passphrase" {
  length  = 40
  special = false
}

resource "random_id" "master_key" {
  byte_length = 32
}

locals {
  master_key_b64 = random_id.master_key.b64_std
  passphrase     = random_password.ca_passphrase.result

  bootstrap_userdata = templatefile("${path.module}/templates/cloud-init.yaml.tpl", {
    release_version = var.release_version
    fqdn            = var.fqdn
    tls_cert_path   = var.tls_cert_path
    tls_key_path    = var.tls_key_path
    data_dir        = var.data_dir
    admin_username  = var.admin_username
    master_key      = local.master_key_b64
    ca_passphrase   = local.passphrase
  })
}

# --- Secret backend ------------------------------------------------------
#
# Three implementations are gated on var.secret_backend. Each writes the
# same logical keys: `nebula-mgmt/<fqdn>/master-key` and
# `nebula-mgmt/<fqdn>/ca-passphrase`. Pick one; the others are no-ops.

resource "aws_secretsmanager_secret" "master_key" {
  count       = var.secret_backend == "aws_secretsmanager" ? 1 : 0
  name        = "nebula-mgmt/${var.fqdn}/master-key"
  description = "NEBULA_MGMT_MASTER_KEY for ${var.fqdn} (base64-encoded 32-byte AES-256 key)."
  kms_key_id  = var.aws_kms_key_id != "" ? var.aws_kms_key_id : null

  tags = {
    application = "nebula-mgmt"
    instance    = var.instance_id
  }
}

resource "aws_secretsmanager_secret_version" "master_key" {
  count          = var.secret_backend == "aws_secretsmanager" ? 1 : 0
  secret_id      = aws_secretsmanager_secret.master_key[0].id
  secret_string  = local.master_key_b64

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "passphrase" {
  count       = var.secret_backend == "aws_secretsmanager" ? 1 : 0
  name        = "nebula-mgmt/${var.fqdn}/ca-passphrase"
  description = "NEBULA_MGMT_CA_PASSPHRASE for ${var.fqdn} (legacy single-CA fallback)."
  kms_key_id  = var.aws_kms_key_id != "" ? var.aws_kms_key_id : null

  tags = {
    application = "nebula-mgmt"
    instance    = var.instance_id
  }
}

resource "aws_secretsmanager_secret_version" "passphrase" {
  count          = var.secret_backend == "aws_secretsmanager" ? 1 : 0
  secret_id      = aws_secretsmanager_secret.passphrase[0].id
  secret_string  = local.passphrase

  lifecycle {
    ignore_changes = [secret_string]
  }
}
