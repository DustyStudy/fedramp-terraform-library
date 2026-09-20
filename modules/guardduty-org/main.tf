# Enables Amazon GuardDuty with organization auto-enrollment for new
# accounts. Deploy from the GuardDuty delegated administrator account.
#
# Unlike the CloudFormation version of this library, GuardDuty
# organization auto-enrollment IS a native Terraform resource
# (aws_guardduty_organization_configuration) — no custom scripting needed.
#
# Note: this module enables the three long-standing protections (S3 Logs,
# Kubernetes Audit Logs, EBS Malware Protection) via the classic
# `datasources` block. GuardDuty has since added newer protections (RDS
# Protection, Lambda Protection, EKS Runtime Monitoring) that may be
# exposed via a newer `feature`-style block depending on your AWS provider
# version — check current provider docs if you want those enabled too.
#
# Control mapping:
#   Rev5 (Moderate/High): SI-4, IR-4, RA-5
#   FedRAMP 20x: KSI-CNA-EIS (automated security assessment/enforcement), KSI-INR-RPI (pattern review feeding incident response)

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id = aws_guardduty_detector.this.id
  auto_enable = var.auto_enable

  datasources {
    s3_logs {
      auto_enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = true
        }
      }
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}


# SNS topics encrypted with the AWS-managed key (alias/aws/sns) silently
# drop messages from events.amazonaws.com: that key's policy can't be edited to
# allow the service to use it. A customer-managed key whose policy trusts
# the publishing service is required for the notification path to work.
data "aws_iam_policy_document" "guardduty_findings_kms" {
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

resource "aws_kms_key" "guardduty_findings" {
  description             = "KMS key for the GuardDuty findings SNS topic"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.guardduty_findings_kms.json
}

resource "aws_sns_topic" "guardduty_findings" {
  name              = "guardduty-findings-medium-plus"
  kms_master_key_id = aws_kms_key.guardduty_findings.arn
}

data "aws_iam_policy_document" "guardduty_findings_topic" {
  statement {
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.guardduty_findings.arn]

    # Only this module's rule may publish (confused-deputy guard).
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_findings.arn]
    }
  }
}

resource "aws_sns_topic_policy" "guardduty_findings" {
  arn    = aws_sns_topic.guardduty_findings.arn
  policy = data.aws_iam_policy_document.guardduty_findings_topic.json
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-findings-to-sns"
  description = "Route GuardDuty findings of Medium severity or higher for alerting/incident response."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_sns_topic.guardduty_findings.arn
}

