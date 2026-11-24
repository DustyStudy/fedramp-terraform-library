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
  type          = "${var.analyzer_type}_UNUSED_ACCESS"

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
    # The exemptions in AWS's reference policy "Allows MFA-authenticated IAM
    # users to manage their own credentials". AWS leaves the two password
    # actions out on purpose and advises against adding them, so they are
    # opt-in here.
    not_actions = concat(
      [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:GetMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      var.allow_password_change_without_mfa ? ["iam:ChangePassword", "iam:GetAccountPasswordPolicy"] : []
    )
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
# A permissions boundary is a ceiling, not a grant: s3:* here caps what the
# developer's identity policy can allow, scoped to this account's ARNs, and the
# Deny statements below carve out the dangerous actions.
#trivy:ignore:AVD-AWS-0345
data "aws_iam_policy_document" "developer_permission_boundary" {
  #checkov:skip=CKV_AWS_107:No credential-issuing action is allowed; the only iam: action is PassRole on the developer role path
  #checkov:skip=CKV_AWS_108:Reads are capped to this account's resources, and the actions that would expose them to other principals (resource policies, ACLs, public access blocks) are denied below. A boundary cannot stop a principal copying data it is allowed to read
  #checkov:skip=CKV_AWS_109:Resource-policy changes are denied below and iam:PassRole is limited to the developer role path
  #checkov:skip=CKV_AWS_110:iam:PassRole is limited to the developer role path and to Lambda; no other iam: action is allowed
  #checkov:skip=CKV_AWS_111:Write access is capped to this account's resources
  #checkov:skip=CKV_AWS_356:Boundary structure requires foundational Allow with overriding Deny blocks

  statement {
    sid     = "AllowScopedServices"
    effect  = "Allow"
    actions = ["dynamodb:*", "lambda:*", "sqs:*", "sns:*"]
    # One ARN per service: IAM rejects a wildcard in the service field.
    resources = [
      for service in ["dynamodb", "lambda", "sqs", "sns"] :
      "arn:${local.partition}:${service}:*:${local.account_id}:*"
    ]
  }

  # S3 ARNs carry no account ID, so ownership is checked with a condition.
  statement {
    sid       = "AllowS3InThisAccount"
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["arn:${local.partition}:s3:::*"]
    condition {
      test     = "StringEquals"
      variable = "s3:ResourceAccount"
      values   = [local.account_id]
    }
  }

  # Lambda is the only allowed service that takes a role. IAM has no condition
  # key for the passed role's boundary, so the path is the control: whoever
  # creates roles under it decides what a developer's function can do.
  statement {
    sid       = "AllowPassDeveloperRolesToLambda"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:role${var.developer_role_path}*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowLambdaLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults"
    ]
    resources = ["arn:${local.partition}:logs:*:${local.account_id}:log-group:/aws/lambda/*"]
  }

  # DescribeLogGroups and StopQuery have no resource type in the Service
  # Authorization Reference, so IAM only matches "*".
  statement {
    sid       = "AllowLogsDiscovery"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups", "logs:StopQuery"]
    resources = ["*"]
  }

  # Data-key use only through the services allowed above; the key policy still
  # has to grant it.
  statement {
    sid       = "AllowKmsViaAllowedServices"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["arn:${local.partition}:kms:*:${local.account_id}:key/*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = [for service in ["dynamodb", "lambda", "s3", "sns", "sqs"] : "${service}.*.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowKmsDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["arn:${local.partition}:kms:*:${local.account_id}:key/*"]
  }

  # The service wildcards above include the actions that hand a resource to
  # another account or to the public.
  # shortcut: SQS and SNS set a policy through the same call as every other
  # attribute and have no condition key to tell them apart, so all attribute
  # changes are denied; a queue or topic can still be created with a policy.
  statement {
    sid    = "DenyResourcePolicyAndPublicAccessChanges"
    effect = "Deny"
    actions = [
      "dynamodb:DeleteResourcePolicy",
      "dynamodb:PutResourcePolicy",
      "lambda:AddLayerVersionPermission",
      "lambda:AddPermission",
      "s3:DeleteBucketPolicy",
      "s3:PutAccountPublicAccessBlock",
      "s3:PutBucketAcl",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "sns:AddPermission",
      "sns:SetTopicAttributes",
      "sqs:AddPermission",
      "sqs:SetQueueAttributes"
    ]
    resources = ["*"]
  }

  # No statement above allows these, so today they are a second lock: they
  # start to matter if role or user management is ever added to the ceiling.
  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "iam:CreateRole",
      "iam:CreateUser",
      "iam:PutRolePolicy",
      "iam:PutUserPolicy",
      "iam:AttachRolePolicy",
      "iam:AttachUserPolicy",
      "iam:PutRolePermissionsBoundary",
      "iam:PutUserPermissionsBoundary"
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:${local.partition}:iam::${local.account_id}:policy/developer-permission-boundary"]
    }
  }

  # Unconditional: with the condition above, removing this boundary from a
  # role that carries it would not have been denied.
  statement {
    sid       = "DenyBoundaryRemoval"
    effect    = "Deny"
    actions   = ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developer_permission_boundary" {
  name        = "developer-permission-boundary"
  description = "FedRAMP Moderate Developer Permission Boundary"
  policy      = data.aws_iam_policy_document.developer_permission_boundary.json
}
