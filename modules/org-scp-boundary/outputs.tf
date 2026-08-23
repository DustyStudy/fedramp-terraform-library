output "policy_id" {
  description = "ID of the created SCP"
  value       = aws_organizations_policy.fedramp_boundary.id
}

output "policy_arn" {
  description = "ARN of the created SCP"
  value       = aws_organizations_policy.fedramp_boundary.arn
}
