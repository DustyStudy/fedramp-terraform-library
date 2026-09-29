# Plan-only tests. The real AWS provider renders policy JSON locally;
# dummy credentials plus overridden identity data keep it from calling AWS.

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
  target = data.aws_region.current
  values = {
    name = "us-east-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws"
  }
}

run "recorder_is_created_and_switched_on" {
  command = plan

  assert {
    condition     = aws_config_configuration_recorder_status.this.is_enabled
    error_message = "The recorder must be switched on, not just created (CM-8, CA-7)."
  }

  assert {
    condition     = one(aws_config_configuration_recorder.this.recording_group).all_supported
    error_message = "The recorder must record every supported resource type."
  }

  assert {
    condition     = aws_s3_bucket.config.bucket == "aws-config-123456789012-us-east-1"
    error_message = "A blank config_bucket_name must default to aws-config-<account>-<region>."
  }
}

run "config_service_can_write_to_its_bucket" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.config_bucket.json).Statement :
      s.Effect == "Allow" && s.Action == "s3:PutObject" && s.Principal.Service == "config.amazonaws.com"
    ])
    error_message = "The bucket policy must let AWS Config deliver history and snapshots."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.config_bucket.json).Statement :
      s.Effect == "Deny" && s.Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "The Config bucket must deny requests made without TLS."
  }
}

run "delivery_is_encrypted_with_a_rotating_cmk" {
  command = plan

  assert {
    condition     = aws_kms_key.config.enable_key_rotation
    error_message = "The Config CMK must rotate (SC-12)."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.config.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "The Config bucket must use SSE-KMS."
  }
}

run "no_conformance_pack_without_a_template" {
  command = plan

  assert {
    condition     = length(aws_config_conformance_pack.this) == 0
    error_message = "No conformance pack should be planned when no template is supplied."
  }
}

run "conformance_pack_from_s3" {
  command = plan

  variables {
    conformance_pack_template_s3_uri = "s3://my-templates/Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
  }

  assert {
    condition     = aws_config_conformance_pack.this[0].template_s3_uri == "s3://my-templates/Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
    error_message = "The conformance pack must use the supplied S3 template."
  }
}

run "rejects_both_template_sources" {
  command = plan

  variables {
    conformance_pack_template_body   = "Resources: {}"
    conformance_pack_template_s3_uri = "s3://my-templates/pack.yaml"
  }

  expect_failures = [aws_config_conformance_pack.this]
}
