output "s3_public_access_block_id" {
  description = "ID of the account-level S3 public access block"
  value       = module.account_baseline.s3_public_access_block_id
}

output "ebs_encryption_enabled" {
  description = "Whether EBS default encryption is enabled"
  value       = module.account_baseline.ebs_encryption_enabled
}
