output "s3_public_access_block_id" {
  description = "ID of the account-level S3 public access block"
  value       = aws_s3_account_public_access_block.this.id
}

output "ebs_encryption_enabled" {
  description = "Whether EBS default encryption is enabled"
  value       = aws_ebs_encryption_by_default.this.enabled
}

output "iam_password_policy_expire_passwords" {
  description = "Indicates whether passwords expire according to the IAM password policy"
  value       = aws_iam_account_password_policy.strict.expire_passwords
}
