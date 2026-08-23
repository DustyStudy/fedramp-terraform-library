output "detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.this.id
}

output "findings_topic_arn" {
  description = <<-EOT
    SNS topic receiving Medium+ severity findings — subscribe your
    incident response team or SOAR pipeline (see moderate/incident-response/
    for IR automation modules).
  EOT
  value       = aws_sns_topic.guardduty_findings.arn
}
