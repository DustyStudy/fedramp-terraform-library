output "expire_passwords" {
  description = "Whether password expiration is active under this policy (true whenever max_password_age > 0)"
  value       = aws_iam_account_password_policy.this.expire_passwords
}
