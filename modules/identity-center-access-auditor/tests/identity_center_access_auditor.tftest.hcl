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
    partition = "aws"
  }
}

# Known ARNs at plan time, so assertions can read the IAM policy and the
# Lambda environment, which reference these resources.
override_resource {
  target          = aws_sns_topic.audit
  override_during = plan
  values = {
    arn = "arn:aws:sns:us-east-1:123456789012:report"
  }
}

override_resource {
  target          = aws_sqs_queue.dlq
  override_during = plan
  values = {
    arn = "arn:aws:sqs:us-east-1:123456789012:dlq"
  }
}

override_resource {
  target          = aws_kms_key.log_encryption
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }
}

run "role_is_read_only" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : [
        for a in s.Action : !startswith(a, "sso:") || startswith(a, "sso:List") || startswith(a, "sso:Describe") || startswith(a, "sso:Get")
      ]
    ]))
    error_message = "The auditor is detective only: its Identity Center permissions must be List/Describe/Get."
  }
}

run "settings_reach_the_lambda" {
  command = plan

  variables {
    sensitive_wildcard_services  = ["iam", "kms"]
    flag_direct_user_assignments = false
  }

  assert {
    condition     = aws_lambda_function.audit.environment[0].variables.SENSITIVE_WILDCARD_SERVICES == "iam,kms"
    error_message = "sensitive_wildcard_services must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.audit.environment[0].variables.FLAG_DIRECT_USER_ASSIGNMENTS == "false"
    error_message = "flag_direct_user_assignments must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.audit.environment[0].variables.AWS_USE_FIPS_ENDPOINT == "true"
    error_message = "The Lambda's SDK calls must use FIPS endpoints by default."
  }
}

run "runs_daily_with_encrypted_logs" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_rule.schedule.schedule_expression == "rate(1 day)"
    error_message = "The audit must run daily by default."
  }

  assert {
    condition     = aws_cloudwatch_log_group.audit.retention_in_days == 365
    error_message = "Lambda logs must be kept for a year (AU-11)."
  }

  assert {
    condition     = length(aws_lambda_function.audit.dead_letter_config) == 1
    error_message = "Failed scheduled invocations must land in a dead-letter queue."
  }
}

run "topic_uses_the_module_cmk" {
  command = plan

  assert {
    condition     = aws_sns_topic.audit.kms_master_key_id == aws_kms_key.log_encryption.arn
    error_message = "The SNS topic must be encrypted with the module's customer-managed key, not aws/sns."
  }
}
