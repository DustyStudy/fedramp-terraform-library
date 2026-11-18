output "s3_public_access_block_id" {
  description = "ID of the account-level S3 public access block"
  value       = aws_s3_account_public_access_block.this.id
}

output "ebs_encryption_enabled" {
  description = "Whether EBS default encryption is enabled"
  value       = aws_ebs_encryption_by_default.this.enabled
}

output "ebs_kms_key_arn" {
  description = "ARN of the CMK set as the default EBS encryption key (the module's own, or kms_key_arn)"
  value       = aws_ebs_default_kms_key.this.key_arn
}

output "iam_password_policy_expire_passwords" {
  description = "Indicates whether passwords expire according to the IAM password policy"
  value       = aws_iam_account_password_policy.strict.expire_passwords
}

output "backup_vault_arn" {
  description = "ARN of the AWS Backup vault (null when create_backup_vault = false)"
  value       = var.create_backup_vault ? aws_backup_vault.this[0].arn : null
}

output "backup_service_role_arn" {
  description = "ARN of AWSBackupDefaultServiceRole (null when create_backup_service_role = false)"
  value       = var.create_backup_service_role ? aws_iam_role.backup[0].arn : null
}
