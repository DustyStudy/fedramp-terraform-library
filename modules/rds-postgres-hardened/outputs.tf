output "db_instance_endpoint" {
  description = "Connection endpoint for the RDS instance"
  value       = aws_db_instance.this.endpoint
}

output "db_instance_arn" {
  description = "ARN of the RDS instance"
  value       = aws_db_instance.this.arn
}

output "master_user_secret_arn" {
  description = "Secrets Manager secret ARN containing master database credentials"
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}
