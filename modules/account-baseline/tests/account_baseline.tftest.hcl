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

run "account_level_guardrails" {
  command = plan

  assert {
    condition = alltrue([
      aws_s3_account_public_access_block.this.block_public_acls,
      aws_s3_account_public_access_block.this.block_public_policy,
      aws_s3_account_public_access_block.this.ignore_public_acls,
      aws_s3_account_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "S3 Block Public Access must be fully on at the account level (AC-3, SC-7)."
  }

  assert {
    condition     = aws_ebs_encryption_by_default.this.enabled
    error_message = "EBS encryption by default must be on (SC-28)."
  }
}

run "password_policy_follows_nist_800_63b_4" {
  command = plan

  assert {
    condition     = aws_iam_account_password_policy.strict.minimum_password_length >= 15
    error_message = "Single-factor passwords must be at least 15 characters by default."
  }

  assert {
    condition     = aws_iam_account_password_policy.strict.max_password_age == 0
    error_message = "Periodic expiry must be off by default (800-63B-4 says SHALL NOT)."
  }
}

run "default_security_group_denies_all_traffic" {
  command = plan

  assert {
    condition     = length(aws_default_security_group.default[0].ingress) == 0 && length(aws_default_security_group.default[0].egress) == 0
    error_message = "The default security group must have no ingress or egress rules (SC-7)."
  }
}

run "backup_vault_gets_a_dedicated_rotating_cmk" {
  command = plan

  assert {
    condition     = length(aws_kms_key.backup) == 1 && aws_kms_key.backup[0].enable_key_rotation
    error_message = "Without a supplied key, the backup vault must get its own rotating CMK (CP-9, SC-12)."
  }
}

run "backup_vault_uses_supplied_key" {
  command = plan

  variables {
    backup_vault_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_kms_key.backup) == 0 && aws_backup_vault.this[0].kms_key_arn == "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    error_message = "A supplied backup_vault_kms_key_arn must be used instead of creating a CMK."
  }
}

run "backup_vault_key_can_be_declared_as_supplied" {
  command = plan

  variables {
    create_backup_vault_kms_key = false
    backup_vault_kms_key_arn    = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_kms_key.backup) == 0
    error_message = "create_backup_vault_kms_key = false must not create a CMK."
  }
}

run "backup_vault_without_any_key_is_rejected" {
  command = plan

  variables {
    create_backup_vault_kms_key = false
  }

  expect_failures = [aws_backup_vault.this]
}
