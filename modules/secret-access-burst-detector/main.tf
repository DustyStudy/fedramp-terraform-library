# Controls: NIST SP 800-53 Rev5 SI-4, AU-6 (relies on AU-2, AU-12 for the
# CloudTrail events it reads). FedRAMP 20x: KSI-MLA-RVL.
#
# A scheduled Lambda correlates CloudTrail events per principal: a burst
# of denied API calls plus a successful secret or parameter read in the
# same window. Detective only.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region

  function_name = "${var.name_prefix}-detect"
  logs_arn      = "arn:${local.partition}:logs:${local.region}:${local.account}:log-group"

  own_log_group_arn        = "${local.logs_arn}:/aws/lambda/${local.function_name}"
  cloudtrail_log_group_arn = "${local.logs_arn}:${var.cloudtrail_log_group_name}"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/detect_secret_access_bursts.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_sns_topic" "findings" {
  name = "${var.name_prefix}-findings"
  # The module's own CMK (AWS-0136); the Lambda role already holds
  # GenerateDataKey/Decrypt on it, which publishing needs.
  kms_master_key_id = aws_kms_key.log_encryption.arn
}

# Only CloudWatch alarms in this account may publish (confused-deputy
# guard). The Lambda publishes through its role's identity policy.
resource "aws_sns_topic_policy" "findings" {
  arn = aws_sns_topic.findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.findings.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description             = "Encrypts the ${var.name_prefix} Lambda's log group, DLQ, SNS topic and environment variables."
  enable_key_rotation     = true
  deletion_window_in_days = 30

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
            "kms:EncryptionContext:aws:logs:arn" = local.own_log_group_arn
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
      {
        # The failure alarms publish to the encrypted topic.
        Sid       = "AllowCloudWatchAlarmsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account }
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
      # Confused-deputy guard: Lambda can assume this role only for a
      # function in this account.
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec" {
  name = "${var.name_prefix}-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Its own log group only, which Terraform creates below.
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${local.own_log_group_arn}:*"
      },
      {
        # Queries only the CloudTrail log group. Both ARN forms, since IAM
        # matches a log group with or without the trailing ":*".
        Effect   = "Allow"
        Action   = ["logs:StartQuery", "logs:GetQueryResults"]
        Resource = [local.cloudtrail_log_group_arn, "${local.cloudtrail_log_group_arn}:*"]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.findings.arn
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

resource "aws_cloudwatch_log_group" "detect" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_lambda_function" "detect" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (CloudWatch Logs
  # and SNS APIs over public AWS endpoints) - no customer VPC resources
  # touched.
  function_name                  = local.function_name
  description                    = "Reports principals with a burst of denied API calls and a successful secret or parameter read in the same window."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "detect_secret_access_bursts.lambda_handler"
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
      SNS_TOPIC_ARN             = aws_sns_topic.findings.arn
      CLOUDTRAIL_LOG_GROUP_NAME = var.cloudtrail_log_group_name
      QUERY_WINDOW_MINUTES      = tostring(var.query_window_minutes)
      DENIED_CALL_THRESHOLD     = tostring(var.denied_call_threshold)
      IGNORED_PRINCIPAL_ARNS    = jsonencode(var.ignored_principal_arns)
      AWS_USE_FIPS_ENDPOINT     = tostring(var.use_fips_endpoint)
    }
  }

  # The role may not create its log group, so it has to exist first.
  depends_on = [aws_cloudwatch_log_group.detect]
}

# A failed run goes straight to the DLQ and the alarms. The default two
# async retries would repeat the queries, and the next scheduled run looks
# at the same window anyway.
resource "aws_lambda_function_event_invoke_config" "detect" {
  function_name          = aws_lambda_function.detect.function_name
  maximum_retry_attempts = 0
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the secret access burst detector on a schedule."
  schedule_expression = var.schedule_expression
  # Off until the account has been tuned: see the README.
  state = var.enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "detect" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.detect.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detect.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name_prefix}-errors"
  alarm_description   = "The ${var.name_prefix} Lambda failed or timed out, so that window was not checked."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.detect.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.findings.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name_prefix}-dlq"
  alarm_description   = "The ${var.name_prefix} dead-letter queue holds a failed run. Stays in alarm until the queue is emptied."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.findings.arn]
}
