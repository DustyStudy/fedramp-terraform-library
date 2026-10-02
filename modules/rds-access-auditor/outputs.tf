output "lambda_function_arn" {
  description = "ARN of the auditor Lambda function."
  value       = aws_lambda_function.audit.arn
}

output "lambda_role_arn" {
  description = "ARN of the auditor's execution role. Member-account roles named by member_role_name must trust it."
  value       = aws_iam_role.lambda_exec.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for audit notifications."
  value       = aws_sns_topic.audit.arn
}

output "member_role_policy_json" {
  description = "Read-only permissions the member-account role needs. Attach it to the role named by member_role_name in each account."
  value       = data.aws_iam_policy_document.member_read.json
}
