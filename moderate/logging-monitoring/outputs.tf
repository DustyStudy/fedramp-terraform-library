output "cis_alarms_topic_arn" {
  description = "SNS topic receiving all CIS/Security Hub CloudWatch alarms plus the MFA and secret-read alarms — subscribe your on-call, ticketing, or SOAR integration here."
  value       = module.logging_monitoring.cis_alarms_topic_arn
}
