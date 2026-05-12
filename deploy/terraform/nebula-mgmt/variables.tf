variable "release_version" {
  description = "Git tag of the nebula-mesh release to install (e.g. v0.3.0). Use `latest` to track the latest GitHub release."
  type        = string
  default     = "latest"
}

variable "fqdn" {
  description = "Public DNS name the management server will be reached at."
  type        = string
}

variable "tls_cert_path" {
  description = "Absolute path on the VM to a pre-staged TLS certificate. Empty means run plain HTTP (only safe behind a TLS-terminating proxy)."
  type        = string
  default     = ""
}

variable "tls_key_path" {
  description = "Absolute path on the VM to the matching private key. Must be set together with tls_cert_path."
  type        = string
  default     = ""
}

variable "instance_id" {
  description = "Provider-specific id of the VM the module will configure. Used only for secret tagging."
  type        = string
}

variable "instance_public_ip" {
  description = "Reachable IPv4 the server will be addressable on."
  type        = string
}

variable "ssh_user" {
  description = "Linux user the cloud-init userdata is run as (e.g. ubuntu, ec2-user, almalinux)."
  type        = string
  default     = "ubuntu"
}

variable "admin_username" {
  description = "Username seeded as the initial admin operator."
  type        = string
  default     = "admin"
}

variable "secret_backend" {
  description = "Where to stash NEBULA_MGMT_MASTER_KEY and NEBULA_MGMT_CA_PASSPHRASE. One of: aws_secretsmanager, gcp_secret_manager, vault_kv."
  type        = string
  default     = "aws_secretsmanager"

  validation {
    condition     = contains(["aws_secretsmanager", "gcp_secret_manager", "vault_kv"], var.secret_backend)
    error_message = "secret_backend must be one of: aws_secretsmanager, gcp_secret_manager, vault_kv."
  }
}

variable "aws_kms_key_id" {
  description = "When secret_backend is aws_secretsmanager, the KMS key encrypting the secrets at rest. Empty uses the default AWS-managed key."
  type        = string
  default     = ""
}

variable "data_dir" {
  description = "Directory on the VM holding the SQLite DB, CA material, and operator data."
  type        = string
  default     = "/var/lib/nebula-mgmt"
}
