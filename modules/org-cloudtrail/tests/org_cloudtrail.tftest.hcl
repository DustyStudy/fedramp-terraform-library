# Plan-only tests. The real AWS provider renders policy JSON locally;
# dummy credentials plus overridden identity data keep it from calling AWS.

provider "aws" {
  region                      = "us-gov-west-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

variables {
  organization_id = "o-abcdef1234"
}

run "trail_covers_the_whole_organization" {
  command = plan

  assert {
    condition     = aws_cloudtrail.org.is_organization_trail && aws_cloudtrail.org.is_multi_region_trail && aws_cloudtrail.org.include_global_service_events
    error_message = "The trail must be an organization trail covering every region and global service events (AU-2, AU-12)."
  }

  assert {
    condition     = aws_cloudtrail.org.enable_log_file_validation
    error_message = "Log file validation must be on so tampering is detectable (AU-9)."
  }
}

run "logs_are_encrypted_with_a_rotating_cmk" {
  command = plan

  assert {
    condition     = aws_kms_key.cloudtrail.enable_key_rotation
    error_message = "The CloudTrail CMK must rotate (SC-12)."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.trail.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "The trail bucket must use SSE-KMS, not SSE-S3."
  }
}

run "buckets_block_public_access_and_version" {
  command = plan

  assert {
    condition = alltrue([
      for b in [aws_s3_bucket_public_access_block.trail, aws_s3_bucket_public_access_block.trail_access_log] :
      b.block_public_acls && b.block_public_policy && b.ignore_public_acls && b.restrict_public_buckets
    ])
    error_message = "Both log buckets must block every form of public access."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.trail.versioning_configuration).status == "Enabled"
    error_message = "The trail bucket must be versioned so deleted logs are recoverable."
  }
}

run "bucket_policy_prevents_confused_deputy_and_plain_http" {
  command = plan

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.s3_cloudtrail_policy.json).Statement :
      s.Condition.StringEquals["aws:SourceArn"] == "arn:aws-us-gov:cloudtrail:us-gov-west-1:123456789012:trail/org-security-trail"
      if s.Effect == "Allow"
    ])
    error_message = "Every CloudTrail grant on the bucket must be pinned to this trail's ARN."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.s3_cloudtrail_policy.json).Statement :
      s.Effect == "Deny" && s.Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "The trail bucket must deny requests made without TLS."
  }
}

run "arns_use_the_current_partition" {
  command = plan

  assert {
    condition     = strcontains(data.aws_iam_policy_document.cloudtrail_kms.json, "arn:aws-us-gov:iam::123456789012:root")
    error_message = "ARNs must use the GovCloud partition when deployed there, not a hardcoded arn:aws."
  }
}

run "rejects_dotted_trail_names" {
  command = plan

  variables {
    trail_name = "org.trail"
  }

  expect_failures = [var.trail_name]
}

run "rejects_malformed_organization_id" {
  command = plan

  variables {
    organization_id = "123456789012"
  }

  expect_failures = [var.organization_id]
}
