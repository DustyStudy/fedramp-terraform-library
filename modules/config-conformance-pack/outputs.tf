output "config_bucket_name" {
  description = "S3 bucket storing AWS Config history and snapshots"
  value       = aws_s3_bucket.config.id
}

output "conformance_pack_name" {
  description = "Name of the deployed conformance pack"
  value       = aws_config_conformance_pack.fedramp_moderate.name
}
