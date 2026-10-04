data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/detect_stale_accounts.py"
  output_path = "${path.module}/build/lambda.zip"
}

# ---------------------------------------------------------------------
# CloudTrail Lake - organization-wide, management events only. Data
# events (S3 object reads, Lambda invocations, etc.) are deliberately
# excluded: they're high-volume, they cost more to ingest, and account
# staleness only needs to know whether *anyone did anything* in an
# account, which management events already capture (including
# ConsoleLogin).
# ---------------------------------------------------------------------
resource "aws_cloudtrail_event_data_store" "org_activity" {
  count = var.create_event_data_store ? 1 : 0

  name                           = "${var.name_prefix}-org-activity"
  organization_enabled           = true
  multi_region_enabled           = true
  retention_period               = var.event_data_store_retention_days
  termination_protection_enabled = true
  kms_key_id                     = aws_kms_key.log_encryption.arn

  advanced_event_selector {
    name = "Management events only"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
}

locals {
  event_data_store_arn = var.create_event_data_store ? aws_cloudtrail_event_data_store.org_activity[0].arn : var.existing_event_data_store_arn
}

# ---------------------------------------------------------------------
# SNS + KMS
# ---------------------------------------------------------------------
resource "aws_sns_topic" "report" {
  name = "${var.name_prefix}-stale-account-report"
  # The module's own CMK (AWS-0136); the Lambda role already holds
  # GenerateDataKey/Decrypt on it, which publishing needs.
  kms_master_key_id = aws_kms_key.log_encryption.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.report.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description         = "Encrypts the ${var.name_prefix} stale-account detector Lambda's log group, DLQ, and environment variables."
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.region}.amazonaws.com" }
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-detect-stale-accounts"
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
          StringEquals = { "kms:CallerAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        # CloudTrail Lake needs this to encrypt the event data store.
        # aws:SourceAccount (not aws:SourceArn) is used deliberately -
        # the key must exist before the event data store does (the
        # store references the key's ARN), so the store's own ARN isn't
        # available yet to scope a SourceArn condition against without
        # a circular dependency. AWS's own docs call this out as a
        # supported, if less strict, alternative for exactly this case.
        Sid       = "AllowCloudTrailToEncryptEventDataStore"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:eventdatastore/*" }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-detector-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

# ---------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-detector-role"

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
  name = "${var.name_prefix}-detector-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        # checkov:skip=CKV_AWS_355: Organizations' list/read APIs for
        # the whole org don't support resource-level scoping.
        Effect = "Allow"
        Action = [
          "organizations:ListAccounts",
          "organizations:ListTagsForResource",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:StartQuery",
          "cloudtrail:GetQueryResults",
          "cloudtrail:DescribeQuery",
        ]
        Resource = local.event_data_store_arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.report.arn
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
    ]
  })
}

# ---------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------
resource "aws_lambda_function" "detector" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (Organizations/
  # CloudTrail Lake/SNS APIs over public AWS endpoints) - no customer
  # VPC resources touched.
  function_name                  = "${var.name_prefix}-detect-stale-accounts"
  description                    = "Scans the org for accounts with no CloudTrail activity in N days."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "detect_stale_accounts.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 300
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrent_executions
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
      SNS_TOPIC_ARN          = aws_sns_topic.report.arn
      EVENT_DATA_STORE_ARN   = local.event_data_store_arn
      ACTIVITY_LOOKBACK_DAYS = tostring(var.activity_lookback_days)
      EXCLUDED_ACCOUNT_IDS   = join(",", var.excluded_account_ids)
      EXEMPT_TAG_KEY         = var.exempt_tag_key
      EXEMPT_TAG_VALUE       = var.exempt_tag_value
      AWS_USE_FIPS_ENDPOINT  = tostring(var.use_fips_endpoint)
    }
  }
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the stale-account scan on a schedule."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "detector" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
