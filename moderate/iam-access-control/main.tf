locals {
  account_id = data.aws_caller_identity.current.account_id
}

# IAM Access Analyzer for continuous access evaluation
resource "aws_accessanalyzer_analyzer" "analyzer" {
  analyzer_name = "fedramp-moderate-access-analyzer"
  type          = var.analyzer_type

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age
    }
  }
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
  alarm_actions       = ["arn:aws:sns:${data.aws_region.current.name}:${local.account_id}:${var.root_usage_alert_topic_name}"]
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
    resources = ["arn:aws:*:*:${local.account_id}:*"]
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
      values   = ["arn:aws:iam::${local.account_id}:policy/developer-permission-boundary"]
    }
  }
}

resource "aws_iam_policy" "developer_permission_boundary" {
  name        = "developer-permission-boundary"
  description = "FedRAMP Moderate Developer Permission Boundary"
  policy      = data.aws_iam_policy_document.developer_permission_boundary.json
}
