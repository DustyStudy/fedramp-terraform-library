locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Key for CloudWatch Logs & ECS Exec Encryption
data "aws_iam_policy_document" "ecs_kms" {
  #checkov:skip=CKV_AWS_109:KMS root account scoping
  #checkov:skip=CKV_AWS_111:KMS key management write access
  #checkov:skip=CKV_AWS_356:KMS key policy wildcard scoping
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Required: CloudWatch Logs makes its own encrypt/decrypt calls as the
  # logs service, not as the IAM principal that created the log group.
  # Without this statement, log delivery to a KMS-encrypted log group
  # fails outright.
  statement {
    sid    = "AllowCloudWatchLogsEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }

  # Note: this key is also referenced by ECS Exec's
  # execute_command_configuration for encrypting the interactive session
  # data channel. That feature separately requires kms:GenerateDataKey/
  # kms:Decrypt for whichever IAM principals actually run
  # `aws ecs execute-command` — since a reusable module can't know who
  # those principals are, grant that access from your root configuration
  # (either here via an additional statement, or as an IAM identity policy
  # on those roles) rather than assuming this module covers it.
}

resource "aws_kms_key" "ecs" {
  description             = "KMS Key for ECS CloudWatch Logs Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ecs_kms.json
}

# CloudWatch Log Group for ECS Task Execution Logs
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/aws/ecs/${var.cluster_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.ecs.arn
}

# ECS Cluster with Container Insights & Encrypted Command Logging
resource "aws_ecs_cluster" "this" {
  name = var.cluster_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      logging    = "OVERRIDE"
      kms_key_id = aws_kms_key.ecs.arn
      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs.name
      }
    }
  }
}
