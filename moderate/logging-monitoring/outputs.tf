output "cis_alarms_topic_arn" {
  description = "SNS topic receiving all 14 CIS/Security Hub CloudWatch alarms — subscribe your on-call, ticketing, or SOAR integration here."
  value       = aws_sns_topic.cis_alarms.arn
}
