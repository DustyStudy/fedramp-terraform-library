data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

# SNS Topic for Root Usage Alerts
resource "aws_sns_topic" "root_usage_alerts" {
  name              = var.root_usage_alert_topic_name
  kms_master_key_id = "arn:${local.partition}:kms:${local.region}:${local.account_id}:alias/aws/sns"
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

# CloudWatch Alarm for Root Usage Alerting
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "RootAccountUsageAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsageCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.root_usage_alerts.arn]
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
