# Central incident-notification SNS topic that aggregates high-severity
# findings from GuardDuty and Security Hub into a single feed for
# incident response tooling (ticketing system, SOAR, on-call paging).
# Complements the per-service topic in modules/guardduty-org — deploy
# this alongside it if you want one aggregated feed rather than several
# separate ones.
#
# Control mapping:
#   Rev5 (Moderate/High): IR-4, IR-5, IR-6
#   FedRAMP 20x: KSI-INR-01 (incident detection capability), KSI-INR-02 (incident response process)

resource "aws_sns_topic" "incident_notifications" {
  name              = "security-incident-notifications"
  kms_master_key_id = "alias/aws/sns"
}

data "aws_iam_policy_document" "incident_notifications_topic" {
  statement {
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.incident_notifications.arn]
  }
}

resource "aws_sns_topic_policy" "incident_notifications" {
  arn    = aws_sns_topic.incident_notifications.arn
  policy = data.aws_iam_policy_document.incident_notifications_topic.json
}

resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name        = "incident-guardduty-high-severity"
  description = "Routes GuardDuty findings at or above the configured severity threshold to the incident topic."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_severity_threshold] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_high_severity" {
  rule = aws_cloudwatch_event_rule.guardduty_high_severity.name
  arn  = aws_sns_topic.incident_notifications.arn
}

resource "aws_cloudwatch_event_rule" "securityhub_critical_high" {
  name        = "incident-securityhub-critical-high"
  description = "Routes Security Hub findings with CRITICAL or HIGH label and an active workflow status to the incident topic."

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_critical_high" {
  rule = aws_cloudwatch_event_rule.securityhub_critical_high.name
  arn  = aws_sns_topic.incident_notifications.arn
}
