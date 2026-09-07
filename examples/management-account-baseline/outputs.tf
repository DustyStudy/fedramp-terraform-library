output "trail_arn" {
  description = "ARN of the organization CloudTrail"
  value       = module.org_cloudtrail.trail_arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID (management account)"
  value       = module.guardduty_org.detector_id
}

output "guardduty_findings_topic_arn" {
  description = "SNS topic receiving Medium+ severity GuardDuty findings"
  value       = module.guardduty_org.findings_topic_arn
}

output "cis_alarms_topic_arn" {
  description = "SNS topic receiving all 14 CIS/Security Hub CloudWatch alarms"
  value       = module.logging_monitoring.cis_alarms_topic_arn
}
