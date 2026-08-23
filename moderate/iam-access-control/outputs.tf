output "external_access_analyzer_arn" {
  description = "ARN of the external-access analyzer"
  value       = aws_accessanalyzer_analyzer.external_access.arn
}

output "unused_access_analyzer_arn" {
  description = "ARN of the unused-access analyzer"
  value       = aws_accessanalyzer_analyzer.unused_access.arn
}

output "permission_boundary_arn" {
  description = "ARN to reference in permissions_boundary when creating human/developer IAM roles or users"
  value       = aws_iam_policy.developer_permission_boundary.arn
}

output "require_mfa_group_name" {
  description = "IAM group name — add users here to enforce MFA"
  value       = aws_iam_group.require_mfa.name
}

output "root_usage_alert_topic_arn" {
  description = "Subscribe your security team's email/Slack integration here"
  value       = aws_sns_topic.root_usage_alerts.arn
}
