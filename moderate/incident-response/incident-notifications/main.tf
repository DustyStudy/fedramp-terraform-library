# Deployable root for modules/incident-notifications. Other roots should call the module
# directly: this root configures its own provider for FIPS endpoints.
module "incident_notifications" {
  source = "../../../modules/incident-notifications"

  guardduty_severity_threshold = var.guardduty_severity_threshold
}

# Resources lived in this root before 1.3.0.
moved {
  from = aws_kms_key.incident_notifications
  to   = module.incident_notifications.aws_kms_key.incident_notifications
}

moved {
  from = aws_sns_topic.incident_notifications
  to   = module.incident_notifications.aws_sns_topic.incident_notifications
}

moved {
  from = aws_sns_topic_policy.incident_notifications
  to   = module.incident_notifications.aws_sns_topic_policy.incident_notifications
}

moved {
  from = aws_cloudwatch_event_rule.guardduty_high_severity
  to   = module.incident_notifications.aws_cloudwatch_event_rule.guardduty_high_severity
}

moved {
  from = aws_cloudwatch_event_target.guardduty_high_severity
  to   = module.incident_notifications.aws_cloudwatch_event_target.guardduty_high_severity
}

moved {
  from = aws_cloudwatch_event_rule.securityhub_critical_high
  to   = module.incident_notifications.aws_cloudwatch_event_rule.securityhub_critical_high
}

moved {
  from = aws_cloudwatch_event_target.securityhub_critical_high
  to   = module.incident_notifications.aws_cloudwatch_event_target.securityhub_critical_high
}
