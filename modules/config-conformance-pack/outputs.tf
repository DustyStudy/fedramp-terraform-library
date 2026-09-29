output "config_bucket_name" {
  description = "S3 bucket storing AWS Config history and snapshots"
  value       = aws_s3_bucket.config.id
}

output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = aws_config_configuration_recorder.this.name
}

output "config_recorder_role_arn" {
  description = "IAM role the Config recorder uses"
  value       = aws_iam_role.config_recorder.arn
}

output "conformance_pack_name" {
  description = "Name of the deployed conformance pack, or null when none is deployed"
  value       = one(aws_config_conformance_pack.this[*].name)
}
