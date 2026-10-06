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

run "single_account_by_default" {
  command = plan

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : !contains(s.Action, "sts:AssumeRole")
    ])
    error_message = "Without member_role_name the Lambda must not be able to assume any role."
  }

  assert {
    condition     = aws_lambda_function.audit.environment[0].variables.MEMBER_ROLE_NAME == ""
    error_message = "The Lambda must scan only its own account by default."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : !contains(s.Action, "organizations:ListAccounts")
    ])
    error_message = "A single-account audit has no reason to list the organization."
  }
}

run "role_is_detective_only" {
  command = plan

  variables {
    member_role_name = "audit-read"
  }

  assert {
    condition = alltrue(flatten([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement : [
        for a in s.Action : can(regex("^(rds|ec2):Describe|^iam:Get|^organizations:List", a)) || contains([
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "sns:Publish", "sqs:SendMessage",
          "kms:Decrypt", "kms:GenerateDataKey*", "xray:PutTraceSegments", "xray:PutTelemetryRecords", "sts:AssumeRole",
        ], a)
      ]
    ]))
    error_message = "The auditor is detective only: it may read RDS, EC2, IAM and Organizations, never change them."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_iam_role_policy.lambda_exec.policy).Statement :
      s.Resource == "arn:aws:iam::*:role/audit-read" if contains(s.Action, "sts:AssumeRole")
    ])
    error_message = "sts:AssumeRole must be scoped to the member role name."
  }

  assert {
    condition = alltrue([
      for a in jsondecode(output.member_role_policy_json).Statement[0].Action :
      can(regex("^(rds|ec2):Describe|^iam:Get", a))
    ])
    error_message = "The member-account policy must be read-only."
  }
}

run "settings_reach_the_lambda" {
  command = plan

  variables {
    member_role_name = "audit-read"
    regions          = ["us-east-1", "us-west-2"]
  }

  assert {
    condition     = aws_lambda_function.audit.environment[0].variables.REGIONS == "us-east-1,us-west-2"
    error_message = "regions must reach the Lambda."
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
    condition     = aws_sns_topic.audit.kms_master_key_id == aws_kms_key.log_encryption.arn
    error_message = "The SNS topic must be encrypted with the module's customer-managed key."
  }
}

run "role_arn_is_rejected_as_member_role_name" {
  command = plan

  variables {
    member_role_name = "arn:aws:iam::123456789012:role/audit-read"
  }

  expect_failures = [var.member_role_name]
}

run "malformed_region_is_rejected" {
  command = plan

  variables {
    regions = ["useast1"]
  }

  expect_failures = [var.regions]
}

run "exec_role_trust_limited_to_this_account" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role.lambda_exec.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "The Lambda execution role trust must carry an aws:SourceAccount condition for this account."
  }
}
