output "workload_perimeter_policy_id" {
  description = "ID of the workload perimeter SCP"
  value       = aws_organizations_policy.workload_perimeter.id
}

output "ai_opt_out_policy_id" {
  description = "ID of the AI Opt-Out Policy"
  value       = aws_organizations_policy.ai_opt_out.id
}

output "backup_policy_id" {
  description = "ID of the Centralized Backup Policy"
  value       = aws_organizations_policy.backup_policy.id
}
