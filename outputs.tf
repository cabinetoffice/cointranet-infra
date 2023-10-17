output "postgres_password" {
  value     = jsondecode(data.aws_secretsmanager_secret_version.postgres_password.secret_string)
  sensitive = true
}

output "application_password" {
  value     = random_password.application_password.result
  sensitive = true
}
