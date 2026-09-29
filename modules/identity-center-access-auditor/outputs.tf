output "lambda_function_arn" {
  description = "ARN of the auditor Lambda function."
  value       = aws_lambda_function.audit.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for audit notifications."
  value       = aws_sns_topic.audit.arn
}
