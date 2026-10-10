output "patch_baseline_id" {
  description = "SSM Patch Baseline ID"
  value       = aws_ssm_patch_baseline.amazon_linux.id
}

output "maintenance_window_id" {
  description = "SSM Maintenance Window ID"
  value       = aws_ssm_maintenance_window.weekly_patch.id
}

output "patch_logs_bucket_arn" {
  description = "S3 Bucket storing patch execution logs"
  value       = aws_s3_bucket.patch_logs.arn
}

output "patch_log_writer_policy_arn" {
  description = "IAM policy to attach to the instance profile role of every patched node, so SSM Agent can write patch output to the encrypted bucket"
  value       = aws_iam_policy.patch_log_writer.arn
}
