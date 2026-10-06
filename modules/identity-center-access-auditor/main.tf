data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/audit_identity_center_access.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_sns_topic" "audit" {
  name = "${var.name_prefix}-identity-center-audit"
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
  description         = "Encrypts the ${var.name_prefix} Identity Center auditor Lambda's log group, DLQ, and environment variables."
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-audit-identity-center"
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
    ]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-audit-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-identity-center-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
      # Confused-deputy guard: Lambda can assume this role only for a
      # function in this account.
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec" {
  name = "${var.name_prefix}-identity-center-auditor-policy"
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
        # checkov:skip=CKV_AWS_355: the IAM Identity Center admin API's
        # IAM Action prefix is "sso:", not "sso-admin:" - "sso-admin" is
        # only the boto3/SDK client name. None of these read/list actions
        # support resource-level scoping to a specific instance or
        # permission set ARN - AWS's own example policies use "*" here.
        Effect = "Allow"
        Action = [
          "sso:ListInstances",
          "sso:ListPermissionSets",
          "sso:DescribePermissionSet",
          "sso:ListManagedPoliciesInPermissionSet",
          "sso:GetInlinePolicyForPermissionSet",
          "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
          "sso:ListAccountsForProvisionedPermissionSet",
          "sso:ListAccountAssignments",
        ]
        Resource = "*"
      },
      {
        # checkov:skip=CKV_AWS_355: these take an IdentityStoreId in the
        # request, not the resource, so IAM can't scope by it.
        Effect = "Allow"
        Action = [
          "identitystore:DescribeUser",
          "identitystore:DescribeGroup",
        ]
        Resource = "*"
      },
      {
        # checkov:skip=CKV_AWS_355: best-effort account-name lookup for
        # readable reports. The Lambda degrades gracefully to raw
        # account IDs if this is denied.
        Effect   = "Allow"
        Action   = ["organizations:ListAccounts"]
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
    ]
  })
}

resource "aws_lambda_function" "audit" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (sso-admin/
  # identitystore/organizations/SNS/SQS APIs over public AWS endpoints) -
  # no customer VPC resources touched.
  function_name                  = "${var.name_prefix}-audit-identity-center"
  description                    = "Audits IAM Identity Center permission sets and account assignments for access-governance risks."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "audit_identity_center_access.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 180
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
    variables = merge(
      {
        SNS_TOPIC_ARN                 = aws_sns_topic.audit.arn
        SENSITIVE_WILDCARD_SERVICES   = join(",", var.sensitive_wildcard_services)
        FLAG_DIRECT_USER_ASSIGNMENTS  = tostring(var.flag_direct_user_assignments)
        REPORT_UNUSED_PERMISSION_SETS = tostring(var.report_unused_permission_sets)
        AWS_USE_FIPS_ENDPOINT         = tostring(var.use_fips_endpoint)
      },
      var.escalation_actions == null ? {} : { ESCALATION_ACTIONS = join(",", var.escalation_actions) },
    )
  }
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/${aws_lambda_function.audit.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the Identity Center access audit on a schedule."
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
