output "lambda_function_arn" {
  description = "ARN of the stale-account detector Lambda function."
  value       = aws_lambda_function.detector.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for the stale-account report."
  value       = aws_sns_topic.report.arn
}

output "event_data_store_arn" {
  description = "ARN of the CloudTrail Lake event data store being queried (created by this module, or the existing one you supplied)."
  value       = local.event_data_store_arn
}
