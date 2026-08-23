output "s3_public_access_block_id" {
  description = "ID of the account-level S3 public access block"
  value       = module.account_baseline.s3_public_access_block_id
}

output "ebs_encryption_enabled" {
  description = "Whether EBS default encryption is enabled"
  value       = module.account_baseline.ebs_encryption_enabled
}

output "ebs_kms_key_arn" {
  description = "ARN of the customer-managed KMS key used for default EBS encryption"
  value       = aws_kms_key.ebs.arn
}
