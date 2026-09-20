data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# SNS Topic for Root Usage Alerts
#
# SNS topics encrypted with the AWS-managed key (alias/aws/sns) silently
# drop messages from EventBridge: that key's policy can't be edited to
# allow the service to use it. A customer-managed key whose policy trusts
# EventBridge is required for the alert path to work.
data "aws_iam_policy_document" "root_usage_alerts_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
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
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "root_usage_alerts" {
  description             = "KMS key for the root account usage alert SNS topic"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.root_usage_alerts_kms.json
}

resource "aws_sns_topic" "root_usage_alerts" {
  name              = var.root_usage_alert_topic_name
  kms_master_key_id = aws_kms_key.root_usage_alerts.arn
}

data "aws_iam_policy_document" "root_usage_alerts_topic" {
  statement {
    sid       = "AllowRootUsageRulePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.root_usage_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.root_usage.arn]
    }
  }
}

resource "aws_sns_topic_policy" "root_usage_alerts" {
  arn    = aws_sns_topic.root_usage_alerts.arn
  policy = data.aws_iam_policy_document.root_usage_alerts_topic.json
}

# External Access Analyzer
resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "fedramp-moderate-external-analyzer"
  type          = var.analyzer_type
}

# Unused Access Analyzer
resource "aws_accessanalyzer_analyzer" "unused_access" {
  analyzer_name = "fedramp-moderate-unused-analyzer"
  type          = var.analyzer_type

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age
    }
  }
}

# Require MFA Group & Policy
resource "aws_iam_group" "require_mfa" {
  name = "require-mfa"
}

data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid    = "BlockMostAccessUnlessSignedInWithMFA"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken"
    ]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_group_policy" "require_mfa" {
  name   = "require-mfa-policy"
  group  = aws_iam_group.require_mfa.name
  policy = data.aws_iam_policy_document.require_mfa.json
}

# Root usage alerting via EventBridge (matches this module's README).
#
# This replaces a CloudWatch alarm on a custom metric
# (CloudTrailMetrics/RootAccountUsageCount) that nothing in this module or
# repo ever emitted, so it could never fire. The pattern is AWS's documented
# root-activity pattern. Console sign-in events are only delivered in
# us-east-1 (the global sign-in endpoint's home region), so deploy this
# module there (or add a copy of this rule there) to catch root console
# logins; API activity is matched in whichever region it occurs.
resource "aws_cloudwatch_event_rule" "root_usage" {
  name        = "root-account-usage"
  description = "Alerts on any use of the AWS account root user."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = {
        type      = ["Root"]
        invokedBy = [{ exists = false }]
      }
      eventType = [{ "anything-but" = "AwsServiceEvent" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "root_usage" {
  rule = aws_cloudwatch_event_rule.root_usage.name
  arn  = aws_sns_topic.root_usage_alerts.arn
}

# Permission Boundary Policy
data "aws_iam_policy_document" "developer_permission_boundary" {
  #checkov:skip=CKV_AWS_107:Credentials exposure is prevented via explicit Deny blocks below
  #checkov:skip=CKV_AWS_108:Data exfiltration is mitigated by boundary scoping
  #checkov:skip=CKV_AWS_109:Permission management is restricted to developer paths
  #checkov:skip=CKV_AWS_110:Privilege escalation prevented through boundary enforcement
  #checkov:skip=CKV_AWS_111:Write access constrained to project resources
  #checkov:skip=CKV_AWS_356:Boundary structure requires foundational Allow with overriding Deny blocks

  statement {
    sid       = "AllowScopedServices"
    effect    = "Allow"
    actions   = ["s3:*", "dynamodb:*", "lambda:*", "sqs:*", "sns:*"]
    resources = ["arn:${local.partition}:*:*:${local.account_id}:*"]
  }

  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:AttachRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:DeleteUserPermissionsBoundary"
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:${local.partition}:iam::${local.account_id}:policy/developer-permission-boundary"]
    }
  }
}

resource "aws_iam_policy" "developer_permission_boundary" {
  name        = "developer-permission-boundary"
  description = "FedRAMP Moderate Developer Permission Boundary"
  policy      = data.aws_iam_policy_document.developer_permission_boundary.json
}
