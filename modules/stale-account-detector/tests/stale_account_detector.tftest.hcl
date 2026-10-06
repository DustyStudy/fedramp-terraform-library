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
  target          = aws_sns_topic.report
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

run "lambda_role_and_member_policy_are_read_only" {
  command = plan

  assert {
    condition = alltrue([
      for action in flatten([for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Action]) :
      can(regex("^(logs:(CreateLogGroup|CreateLogStream|PutLogEvents)|sns:Publish|sqs:SendMessage|kms:(Decrypt|GenerateDataKey\\*)|xray:Put(TraceSegments|TelemetryRecords)|[a-z-]+:(List|Get|Describe|Lookup|GenerateCredentialReport))", action))
    ])
    error_message = "The Lambda role must hold only read actions plus its own logging, topic, DLQ and key use."
  }

  assert {
    condition = alltrue([
      for action in flatten([for s in jsondecode(data.aws_iam_policy_document.member_read.json).Statement : s.Action]) :
      can(regex("^iam:(List|Get|GenerateCredentialReport)", action))
    ])
    error_message = "The member role policy must be read-only IAM."
  }

  assert {
    condition     = !contains(flatten([for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Action]), "sts:AssumeRole")
    error_message = "Without member_role_name the Lambda must not be able to assume any role."
  }
}

run "assume_role_is_limited_to_the_member_role" {
  command = plan

  variables {
    member_role_name = "StaleAccountRead"
  }

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : s.Resource
      if contains(flatten([s.Action]), "sts:AssumeRole")
    ] == ["arn:aws:iam::*:role/StaleAccountRead"]
    error_message = "sts:AssumeRole must name only the member role."
  }
}

run "settings_reach_the_lambda" {
  command = plan

  variables {
    inactivity_days    = 35
    member_role_name   = "StaleAccountRead"
    ignored_role_names = ["ProwlerScan", "OtherScanner"]
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.INACTIVITY_DAYS == "35"
    error_message = "inactivity_days must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.MEMBER_ROLE_NAME == "StaleAccountRead"
    error_message = "member_role_name must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.IGNORED_ROLE_NAMES == "ProwlerScan,OtherScanner"
    error_message = "ignored_role_names must reach the Lambda."
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.AWS_USE_FIPS_ENDPOINT == "true"
    error_message = "FIPS endpoints must be on by default."
  }

  assert {
    condition     = aws_lambda_function.detector.timeout == 900
    error_message = "The Lambda needs the maximum timeout for event history lookups."
  }
}

run "rejects_a_window_longer_than_event_history" {
  command = plan

  variables {
    inactivity_days = 91
  }

  expect_failures = [var.inactivity_days]
}

run "rejects_a_role_arn_as_the_member_role_name" {
  command = plan

  variables {
    member_role_name = "arn:aws:iam::123456789012:role/StaleAccountRead"
  }

  expect_failures = [var.member_role_name]
}

run "lambda_is_encrypted_and_has_a_dlq" {
  command = plan

  assert {
    condition     = aws_kms_key.log_encryption.enable_key_rotation
    error_message = "The customer-managed key must rotate (SC-12)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.detector.retention_in_days == 365
    error_message = "Lambda logs must be kept for a year (AU-11)."
  }

  assert {
    condition     = length(aws_lambda_function.detector.dead_letter_config) == 1
    error_message = "Failed scheduled invocations must land in a dead-letter queue."
  }
}

run "topic_uses_the_module_cmk" {
  command = plan

  assert {
    condition     = aws_sns_topic.report.kms_master_key_id == aws_kms_key.log_encryption.arn
    error_message = "The SNS topic must be encrypted with the module's customer-managed key, not aws/sns."
  }
}

run "exec_role_trust_limited_to_this_account" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role.lambda_exec.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "The Lambda execution role trust must carry an aws:SourceAccount condition for this account."
  }
}
