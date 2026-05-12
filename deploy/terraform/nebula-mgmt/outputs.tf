output "server_url" {
  description = "Base URL the management server will answer on once cloud-init finishes."
  value       = var.tls_cert_path != "" ? "https://${var.fqdn}:8080" : "http://${var.fqdn}:8080"
}

output "master_key_secret_arn" {
  description = "ARN / id of the secret holding NEBULA_MGMT_MASTER_KEY (empty when using a non-AWS backend)."
  value       = var.secret_backend == "aws_secretsmanager" ? aws_secretsmanager_secret.master_key[0].arn : ""
}

output "passphrase_secret_arn" {
  description = "ARN / id of the secret holding the legacy CA passphrase (empty when using a non-AWS backend)."
  value       = var.secret_backend == "aws_secretsmanager" ? aws_secretsmanager_secret.passphrase[0].arn : ""
}

output "cloud_init_userdata" {
  description = "Rendered cloud-init user-data — attach this to the VM resource (e.g. aws_instance.user_data)."
  value       = local.bootstrap_userdata
  sensitive   = true
}
