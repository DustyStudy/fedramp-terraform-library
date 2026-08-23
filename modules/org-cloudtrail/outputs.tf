output "trail_arn" {
  description = "ARN of the organization CloudTrail"
  value       = aws_cloudtrail.org.arn
}

output "log_bucket_name" {
  description = "S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.trail.id
}

output "access_log_bucket_name" {
  description = "S3 bucket storing server access logs for the CloudTrail log bucket"
  value       = aws_s3_bucket.trail_access_log.id
}

output "log_group_name" {
  description = "CloudWatch Logs group for real-time trail analysis"
  value       = aws_cloudwatch_log_group.trail.name
}

output "kms_key_arn" {
  description = "KMS key used to encrypt trail logs"
  value       = aws_kms_key.cloudtrail.arn
}
