output "lambda_function_arn" {
  description = "ARN of the stale-account detector Lambda function."
  value       = aws_lambda_function.detector.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for the stale-account report."
  value       = aws_sns_topic.report.arn
}

output "lambda_role_arn" {
  description = "The Lambda's role. Trust it in the member-account role named by member_role_name."
  value       = aws_iam_role.lambda_exec.arn
}

output "member_role_policy_json" {
  description = "Read-only permissions the member-account role needs. Attach it to the role named by member_role_name in each account."
  value       = data.aws_iam_policy_document.member_read.json
}
