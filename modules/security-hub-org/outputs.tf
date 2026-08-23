output "security_hub_account_id" {
  description = "ID of the Security Hub account resource (indicates Security Hub is enabled)"
  value       = aws_securityhub_account.this.id
}
