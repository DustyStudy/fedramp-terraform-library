# Central incident-notification SNS topic that aggregates high-severity
# findings from GuardDuty and Security Hub into a single feed for
# incident response tooling (ticketing system, SOAR, on-call paging).
# Complements the per-service topic in modules/guardduty-org — deploy
# this alongside it if you want one aggregated feed rather than several
# separate ones.
#
# Control mapping:
#   Rev5 (Moderate/High): IR-4, IR-5, IR-6
#   FedRAMP 20x: KSI-INR-RIR (review effectiveness of documented IR procedures), KSI-INR-AAR (after-action reports)

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}


# SNS topics encrypted with the AWS-managed key (alias/aws/sns) silently
# drop messages from events.amazonaws.com: that key's policy can't be edited to
# allow the service to use it. A customer-managed key whose policy trusts
# the publishing service is required for the notification path to work.
data "aws_iam_policy_document" "incident_notifications_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "incident_notifications" {
  description             = "KMS key for the security incident notification SNS topic"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.incident_notifications_kms.json
}

resource "aws_sns_topic" "incident_notifications" {
  name              = "security-incident-notifications"
  kms_master_key_id = aws_kms_key.incident_notifications.arn
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

    # Only this module's two rules may publish (confused-deputy guard).
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.guardduty_high_severity.arn,
        aws_cloudwatch_event_rule.securityhub_critical_high.arn,
      ]
    }
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
