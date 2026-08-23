locals {
  account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

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

# ECS Cluster with Container Insights Enabled (CKV_AWS_65)
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
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs.name
      }
    }
  }
}
