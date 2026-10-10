# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

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

variables {
  use_fips_endpoint = false
}

run "bucket_names_fit_s3_with_a_current_vpc_id" {
  command = plan

  variables {
    vpc_id = "vpc-0a5c93c241c2cd7d7"
  }

  assert {
    condition     = length(aws_s3_bucket.flow_log.bucket) <= 63 && length(aws_s3_bucket.flow_log_access_log.bucket) <= 63
    error_message = "Both bucket names must fit S3's 63-character limit with a 17-character VPC ID."
  }
}

run "older_vpc_ids_keep_the_long_access_log_name" {
  command = plan

  variables {
    vpc_id = "vpc-1a2b3c4d"
  }

  assert {
    condition     = aws_s3_bucket.flow_log_access_log.bucket == "vpc-flow-logs-access-logs-123456789012-us-east-1-vpc-1a2b3c4d"
    error_message = "A name that already fits must not change, or existing buckets would be replaced."
  }
}

run "log_delivery_key_grant_is_scoped_to_this_account" {
  command = plan

  variables {
    vpc_id = "vpc-0a5c93c241c2cd7d7"
  }

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.flow_log_kms.json).Statement :
      try(s.Condition.StringEquals["aws:SourceAccount"], "") == "123456789012" &&
      try(s.Condition.ArnLike["aws:SourceArn"], "") == "arn:${data.aws_partition.current.partition}:logs:us-east-1:123456789012:*"
      if try(s.Principal.Service, "") == "delivery.logs.amazonaws.com"
    ])
    error_message = "The log-delivery grant on the key must carry both source conditions."
  }
}
