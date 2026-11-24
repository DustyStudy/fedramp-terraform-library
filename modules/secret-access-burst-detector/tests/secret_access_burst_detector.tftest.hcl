# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS. The archive provider zips the Lambda
# locally.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

# Known ARNs at plan time, so assertions can read the IAM policy and the
# Lambda environment, which reference these resources. Override values
# cannot reference data sources, so these three fixtures spell the
# partition out.
override_resource {
  target          = aws_sns_topic.findings
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:sns:us-east-1:123456789012:findings"
  }
}

override_resource {
  target          = aws_sqs_queue.dlq
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:sqs:us-east-1:123456789012:dlq"
  }
}

override_resource {
  target          = aws_kms_key.log_encryption
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }
}

variables {
  cloudtrail_log_group_name = "aws-cloudtrail-logs"
}

run "off_by_default" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_rule.schedule.state == "DISABLED"
    error_message = "The detector must not run until the caller sets enabled = true."
  }
}

run "enabled_runs_every_15_minutes_over_60" {
  command = plan

  variables {
    enabled = true
  }

  assert {
    condition     = aws_cloudwatch_event_rule.schedule.state == "ENABLED" && aws_cloudwatch_event_rule.schedule.schedule_expression == "rate(15 minutes)"
    error_message = "With enabled = true the rule must be on, every 15 minutes by default."
  }

  assert {
    condition     = aws_lambda_function.detect.environment[0].variables.QUERY_WINDOW_MINUTES == "60" && aws_lambda_function.detect.environment[0].variables.DENIED_CALL_THRESHOLD == "20"
    error_message = "Defaults are a 60-minute window and 20 denied calls."
  }
}

run "role_can_query_only_the_cloudtrail_log_group" {
  command = plan

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Resource if contains(s.Action, "logs:StartQuery")
      ] == [[
        "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs",
        "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs:*",
    ]]
    error_message = "logs:StartQuery must be scoped to the CloudTrail log group, in the current partition."
  }

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Resource if contains(s.Action, "logs:GetQueryResults")
      ] == [[
        "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs",
        "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs:*",
    ]]
    error_message = "logs:GetQueryResults must be scoped to the CloudTrail log group, not \"*\"."
  }

  assert {
    condition     = data.aws_partition.current.partition == "aws-us-gov"
    error_message = "These runs plan against a non-commercial partition, so an ARN hardcoded to the commercial one fails the assertions above and below."
  }

  assert {
    condition = toset(flatten([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Action if s.Resource == "*"
    ])) == toset(["xray:PutTraceSegments", "xray:PutTelemetryRecords"])
    error_message = "Only actions with no resource type to scope to may use Resource \"*\"."
  }

  assert {
    condition = toset(flatten([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Action
      ])) == toset([
      "logs:CreateLogStream", "logs:PutLogEvents", "logs:StartQuery", "logs:GetQueryResults", "sns:Publish",
      "sqs:SendMessage", "kms:Decrypt", "kms:GenerateDataKey*", "xray:PutTraceSegments", "xray:PutTelemetryRecords",
    ])
    error_message = "The detector is detective only: it may query logs and publish findings, nothing else."
  }

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Resource if contains(s.Action, "logs:PutLogEvents")
    ] == ["arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:/aws/lambda/secret-access-burst-detector-detect:*"]
    error_message = "The Lambda may write only to its own log group."
  }

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Resource if contains(s.Action, "sns:Publish")
    ] == [aws_sns_topic.findings.arn]
    error_message = "sns:Publish must be scoped to the module's topic."
  }
}

run "settings_reach_the_lambda" {
  command = plan

  variables {
    query_window_minutes   = 90
    denied_call_threshold  = 50
    ignored_principal_arns = ["arn:*:sts::123456789012:assumed-role/scanner/*"]
  }

  assert {
    condition     = aws_lambda_function.detect.environment[0].variables.CLOUDTRAIL_LOG_GROUP_NAME == "aws-cloudtrail-logs"
    error_message = "cloudtrail_log_group_name must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.detect.environment[0].variables.QUERY_WINDOW_MINUTES == "90" && aws_lambda_function.detect.environment[0].variables.DENIED_CALL_THRESHOLD == "50"
    error_message = "query_window_minutes and denied_call_threshold must reach the Lambda."
  }

  assert {
    condition     = jsondecode(aws_lambda_function.detect.environment[0].variables.IGNORED_PRINCIPAL_ARNS) == ["arn:*:sts::123456789012:assumed-role/scanner/*"]
    error_message = "ignored_principal_arns must reach the Lambda as a JSON list."
  }

  assert {
    condition     = aws_lambda_function.detect.environment[0].variables.AWS_USE_FIPS_ENDPOINT == "true"
    error_message = "The Lambda's SDK calls must use FIPS endpoints by default."
  }
}

run "logs_and_topic_use_a_rotating_cmk" {
  command = plan

  assert {
    condition     = aws_kms_key.log_encryption.enable_key_rotation && aws_kms_key.log_encryption.deletion_window_in_days == 30
    error_message = "The module CMK must rotate and have an explicit deletion window."
  }

  assert {
    condition     = aws_sns_topic.findings.kms_master_key_id == aws_kms_key.log_encryption.arn
    error_message = "The SNS topic must be encrypted with the module's customer-managed key, not aws/sns."
  }

  assert {
    condition     = aws_cloudwatch_log_group.detect.kms_key_id == aws_kms_key.log_encryption.arn && aws_cloudwatch_log_group.detect.retention_in_days == 365
    error_message = "Lambda logs must be encrypted with the module CMK and kept for a year (AU-11)."
  }

  assert {
    condition     = aws_lambda_function.detect.kms_key_arn == aws_kms_key.log_encryption.arn
    error_message = "The Lambda environment variables must be encrypted with the module CMK."
  }

  assert {
    condition     = aws_sqs_queue.dlq.kms_master_key_id == aws_kms_key.log_encryption.arn
    error_message = "The dead-letter queue must be encrypted with the module CMK, not aws/sqs."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.log_encryption.policy).Statement :
      try(s.Condition.ArnLike["kms:EncryptionContext:aws:logs:arn"], "") == "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:log-group:/aws/lambda/secret-access-burst-detector-detect"
    ])
    error_message = "CloudWatch Logs may use the CMK only for the Lambda's own log group."
  }
}

run "exec_role_trust_limited_to_this_account" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role.lambda_exec.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "The Lambda execution role trust must carry an aws:SourceAccount condition for this account."
  }
}

run "failed_runs_alarm_and_are_not_retried" {
  command = plan

  assert {
    condition     = aws_lambda_function_event_invoke_config.detect.maximum_retry_attempts == 0 && length(aws_lambda_function.detect.dead_letter_config) == 1
    error_message = "A failed run must go to the DLQ without async retries."
  }

  assert {
    condition = alltrue([
      for a in [aws_cloudwatch_metric_alarm.errors, aws_cloudwatch_metric_alarm.dlq] :
      a.alarm_actions == toset([aws_sns_topic.findings.arn])
    ])
    error_message = "Both failure alarms must notify the module's SNS topic."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_sns_topic_policy.findings.policy).Statement :
      s.Principal.Service == "cloudwatch.amazonaws.com" && s.Action == "sns:Publish" && s.Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    ])
    error_message = "The topic policy must let only this account's CloudWatch alarms publish."
  }
}

run "zero_threshold_is_rejected" {
  command = plan

  variables {
    denied_call_threshold = 0
  }

  expect_failures = [var.denied_call_threshold]
}

run "zero_window_is_rejected" {
  command = plan

  variables {
    query_window_minutes = 0
  }

  expect_failures = [var.query_window_minutes]
}

run "zero_reserved_concurrency_is_rejected" {
  command = plan

  variables {
    reserved_concurrent_executions = 0
  }

  expect_failures = [var.reserved_concurrent_executions]
}

run "log_group_arn_or_pattern_is_rejected" {
  command = plan

  variables {
    cloudtrail_log_group_name = "aws-cloudtrail-logs:*"
  }

  expect_failures = [var.cloudtrail_log_group_name]
}

run "ignore_everything_pattern_is_rejected" {
  command = plan

  variables {
    ignored_principal_arns = ["*"]
  }

  expect_failures = [var.ignored_principal_arns]
}
