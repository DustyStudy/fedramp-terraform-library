output "default_security_group_id" {
  description = "ID of the locked-down default security group"
  value       = aws_default_security_group.this.id
}
