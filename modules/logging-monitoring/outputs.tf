output "cis_alarms_topic_arn" {
  description = "SNS topic receiving all CIS/Security Hub CloudWatch alarms plus the MFA and secret-read alarms — subscribe your on-call, ticketing, or SOAR integration here."
  value       = aws_sns_topic.cis_alarms.arn
}
