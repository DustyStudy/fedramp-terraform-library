output "flow_log_id" {
  description = "ID of the VPC Flow Log"
  value       = aws_flow_log.this.id
}

output "flow_log_bucket_name" {
  description = "S3 bucket storing flow log records"
  value       = aws_s3_bucket.flow_log.id
}
