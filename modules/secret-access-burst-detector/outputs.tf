output "lambda_function_arn" {
  description = "ARN of the detector Lambda function."
  value       = aws_lambda_function.detect.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic findings and failure alarms are sent to."
  value       = aws_sns_topic.findings.arn
}
