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

override_resource {
  target          = aws_cloudtrail_event_data_store.org_activity
  override_during = plan
  values = {
    arn = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }
}

run "creates_an_org_wide_management_events_store" {
  command = plan

  assert {
    condition     = aws_cloudtrail_event_data_store.org_activity[0].organization_enabled && aws_cloudtrail_event_data_store.org_activity[0].multi_region_enabled
    error_message = "The event data store must cover every account and region in the organization."
  }

  assert {
    condition     = aws_cloudtrail_event_data_store.org_activity[0].termination_protection_enabled
    error_message = "Deleting the store deletes its history, so termination protection must be on."
  }

  assert {
    condition     = tolist(one(one(aws_cloudtrail_event_data_store.org_activity[0].advanced_event_selector).field_selector).equals) == tolist(["Management"])
    error_message = "The store must ingest management events only, to keep ingestion cost down."
  }
}

run "reuses_an_existing_store_when_asked" {
  command = plan

  variables {
    create_event_data_store       = false
    existing_event_data_store_arn = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_cloudtrail_event_data_store.org_activity) == 0
    error_message = "No new event data store may be created when an existing one is supplied."
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.EVENT_DATA_STORE_ARN == "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/11111111-2222-3333-4444-555555555555"
    error_message = "The Lambda must query the supplied event data store."
  }
}

run "lambda_uses_fips_endpoints_and_the_lookback" {
  command = plan

  variables {
    activity_lookback_days = 120
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.AWS_USE_FIPS_ENDPOINT == "true"
    error_message = "The Lambda's SDK calls must use FIPS endpoints by default."
  }

  assert {
    condition     = aws_lambda_function.detector.environment[0].variables.ACTIVITY_LOOKBACK_DAYS == "120"
    error_message = "activity_lookback_days must reach the Lambda."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.schedule.schedule_expression == "rate(7 days)"
    error_message = "The scan must run weekly by default."
  }
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
