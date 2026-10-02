data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region

  # Everything the audit reads in an account. None of these support
  # resource-level scoping to "only what exists", so they take "*".
  read_actions = [
    "rds:DescribeDBInstances",
    "rds:DescribeDBClusters",
    "rds:DescribeDBParameters",
    "rds:DescribeDBClusterParameters",
    "ec2:DescribeSecurityGroups",
    "iam:GetAccountAuthorizationDetails",
  ]
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/audit_rds_access.py"
  output_path = "${path.module}/build/lambda.zip"
}

data "aws_iam_policy_document" "member_read" {
  statement {
    # checkov:skip=CKV_AWS_356: list/read actions that don't support
    # resource-level permissions.
    sid       = "RdsAccessAuditRead"
    actions   = local.read_actions
    resources = ["*"]
  }
}

resource "aws_sns_topic" "audit" {
  name = "${var.name_prefix}-audit"
  # The module's own CMK (AWS-0136); the Lambda role already holds
  # GenerateDataKey/Decrypt on it, which publishing needs.
  kms_master_key_id = aws_kms_key.log_encryption.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.audit.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description         = "Encrypts the ${var.name_prefix} Lambda's log group, DLQ, SNS topic and environment variables."
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.region}:${local.account}:log-group:/aws/lambda/${var.name_prefix}-audit"
          }
        }
      },
      {
        Sid       = "AllowSQSUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "sqs.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:CallerAccount" = local.account }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec" {
  name = "${var.name_prefix}-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect   = "Allow"
          Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
          Resource = "arn:${local.partition}:logs:${local.region}:${local.account}:*"
        },
        {
          # checkov:skip=CKV_AWS_355: list/read actions that don't
          # support resource-level permissions.
          Effect   = "Allow"
          Action   = local.read_actions
          Resource = "*"
        },
        {
          Effect   = "Allow"
          Action   = ["sns:Publish"]
          Resource = aws_sns_topic.audit.arn
        },
        {
          Effect   = "Allow"
          Action   = ["sqs:SendMessage"]
          Resource = aws_sqs_queue.dlq.arn
        },
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
          Resource = aws_kms_key.log_encryption.arn
        },
        {
          Effect   = "Allow"
          Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
          Resource = "*"
        },
      ],
      var.member_role_name == "" ? [] : [
        {
          # checkov:skip=CKV_AWS_355: lists the accounts to scan.
          Effect   = "Allow"
          Action   = ["organizations:ListAccounts"]
          Resource = "*"
        },
        {
          # Only the one named role, in any account. An account without
          # it fails to assume and is listed as "not scanned".
          Effect   = "Allow"
          Action   = ["sts:AssumeRole"]
          Resource = "arn:${local.partition}:iam::*:role/${var.member_role_name}"
        },
      ],
    )
  })
}

resource "aws_lambda_function" "audit" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (RDS, EC2, IAM,
  # Organizations, STS and SNS APIs over public AWS endpoints) - it never
  # connects to a database, so it needs no VPC.
  function_name                  = "${var.name_prefix}-audit"
  description                    = "Audits RDS and Aurora public exposure, master credentials, IAM authentication, TLS enforcement and IAM rds-db:connect scope."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "audit_rds_access.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 600
  memory_size                    = 256
  reserved_concurrent_executions = 2
  filename                       = data.archive_file.lambda_zip.output_path
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256
  kms_key_arn                    = aws_kms_key.log_encryption.arn
  code_signing_config_arn        = var.code_signing_config_arn

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.audit.arn
      MEMBER_ROLE_NAME      = var.member_role_name
      REGIONS               = join(",", var.regions)
      AWS_USE_FIPS_ENDPOINT = tostring(var.use_fips_endpoint)
    }
  }
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/${aws_lambda_function.audit.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the RDS access audit on a schedule."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "audit" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.audit.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
