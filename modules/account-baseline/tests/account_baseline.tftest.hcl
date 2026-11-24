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

# No Auto Scaling service-linked role unless a run says otherwise.
override_data {
  target = data.aws_iam_roles.autoscaling
  values = {
    arns = []
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

run "creates_the_backup_role_the_org_policy_names" {
  command = plan

  assert {
    condition     = aws_iam_role.backup[0].name == "AWSBackupDefaultServiceRole" && aws_iam_role.backup[0].path == "/service-role/"
    error_message = "org-governance's backup policy runs jobs as service-role/AWSBackupDefaultServiceRole; it must exist."
  }

  assert {
    condition     = jsondecode(aws_iam_role.backup[0].assume_role_policy).Statement[0].Principal.Service == "backup.amazonaws.com"
    error_message = "Only AWS Backup may assume the backup role."
  }

  assert {
    condition     = toset([for a in aws_iam_role_policy_attachment.backup : a.policy_arn]) == toset([for p in ["AWSBackupServiceRolePolicyForBackup", "AWSBackupServiceRolePolicyForRestores"] : "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/${p}"])
    error_message = "The backup role needs the AWS managed backup and restore policies."
  }
}

run "backup_role_can_be_skipped" {
  command = plan

  variables {
    create_backup_service_role = false
  }

  assert {
    condition     = length(aws_iam_role.backup) == 0 && length(aws_iam_role_policy_attachment.backup) == 0
    error_message = "create_backup_service_role = false must not create the role, for a second region or an account that has it."
  }
}

run "ebs_default_key_is_a_rotating_cmk" {
  command = plan

  assert {
    condition     = length(aws_kms_key.ebs) == 1 && aws_kms_key.ebs[0].enable_key_rotation && aws_kms_key.ebs[0].deletion_window_in_days == 30
    error_message = "Without a supplied key, default EBS encryption must get its own rotating CMK, not aws/ebs (SC-12, SC-28)."
  }

  assert {
    condition     = [for s in jsondecode(aws_kms_key.ebs[0].policy).Statement : s.Sid] == ["AllowRootAccountAdmin"]
    error_message = "With no Auto Scaling service-linked role in the account the key policy must not name it; KMS rejects a missing principal."
  }
}

run "ebs_key_grants_the_autoscaling_role_when_it_exists" {
  command = plan

  override_data {
    target = data.aws_iam_roles.autoscaling
    values = {
      arns = ["arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }
  }

  assert {
    condition = one([
      for s in jsondecode(aws_kms_key.ebs[0].policy).Statement : s
      if s.Sid == "AllowAutoScalingUseOfTheKey"
      ]) == {
      Sid       = "AllowAutoScalingUseOfTheKey"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" }
      Action    = ["kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Encrypt", "kms:DescribeKey", "kms:Decrypt"]
      Resource  = "*"
    }
    error_message = "The Auto Scaling service-linked role needs the AWS-documented use permissions on the EBS key."
  }

  assert {
    condition = one([
      for s in jsondecode(aws_kms_key.ebs[0].policy).Statement : s
      if s.Sid == "AllowAutoScalingAttachmentOfPersistentResources"
      ]) == {
      Sid       = "AllowAutoScalingAttachmentOfPersistentResources"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" }
      Action    = "kms:CreateGrant"
      Resource  = "*"
      Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
    }
    error_message = "kms:CreateGrant for Auto Scaling must be limited to grants for AWS resources."
  }
}

run "ebs_key_autoscaling_grant_can_be_turned_off" {
  command = plan

  variables {
    ebs_kms_key_grant_autoscaling = false
  }

  override_data {
    target = data.aws_iam_roles.autoscaling
    values = {
      arns = ["arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }
  }

  assert {
    condition     = [for s in jsondecode(aws_kms_key.ebs[0].policy).Statement : s.Sid] == ["AllowRootAccountAdmin"]
    error_message = "ebs_kms_key_grant_autoscaling = false must leave the Auto Scaling role out of the key policy."
  }
}

run "ebs_default_key_uses_supplied_key" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_kms_key.ebs) == 0 && aws_ebs_default_kms_key.this.key_arn == "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    error_message = "A supplied kms_key_arn must become the default EBS key instead of a module-created CMK."
  }
}

run "ebs_key_can_be_declared_as_supplied" {
  command = plan

  variables {
    set_ebs_default_kms_key = true
    kms_key_arn             = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = length(aws_kms_key.ebs) == 0
    error_message = "set_ebs_default_kms_key = true must not create a CMK."
  }
}

run "ebs_default_key_without_any_key_is_rejected" {
  command = plan

  variables {
    set_ebs_default_kms_key = true
  }

  expect_failures = [aws_ebs_default_kms_key.this]
}

run "ebs_key_deletion_window_is_bounded" {
  command = plan

  variables {
    ebs_kms_key_deletion_window_in_days = 5
  }

  expect_failures = [var.ebs_kms_key_deletion_window_in_days]
}

run "backup_vault_is_unlocked_and_unprotected_by_default" {
  command = plan

  assert {
    condition     = length(aws_backup_vault_lock_configuration.this) == 0 && length(aws_backup_vault_policy.protect) == 0
    error_message = "Vault Lock and the deny policy are opt-in: compliance mode cannot be undone."
  }
}

run "backup_vault_lock_compliance_mode" {
  command = plan

  variables {
    backup_vault_lock_min_retention_days  = 7
    backup_vault_lock_max_retention_days  = 365
    backup_vault_lock_changeable_for_days = 3
  }

  assert {
    condition = (
      aws_backup_vault_lock_configuration.this[0].backup_vault_name == "FedRAMPComplianceVault" &&
      aws_backup_vault_lock_configuration.this[0].min_retention_days == 7 &&
      aws_backup_vault_lock_configuration.this[0].max_retention_days == 365 &&
      aws_backup_vault_lock_configuration.this[0].changeable_for_days == 3
    )
    error_message = "Vault Lock must lock the module's vault with the requested retention and grace period (CP-9, SI-7)."
  }
}

run "backup_vault_lock_rejects_short_grace_period" {
  command = plan

  variables {
    backup_vault_lock_min_retention_days  = 7
    backup_vault_lock_changeable_for_days = 1
  }

  expect_failures = [var.backup_vault_lock_changeable_for_days]
}

run "backup_vault_lock_rejects_max_below_min" {
  command = plan

  variables {
    backup_vault_lock_min_retention_days = 30
    backup_vault_lock_max_retention_days = 7
  }

  expect_failures = [var.backup_vault_lock_max_retention_days]
}

run "backup_vault_lock_needs_the_vault" {
  command = plan

  variables {
    create_backup_vault                  = false
    backup_vault_lock_min_retention_days = 7
  }

  expect_failures = [var.backup_vault_lock_min_retention_days]
}

run "backup_vault_lock_governance_mode" {
  command = plan

  variables {
    backup_vault_lock_min_retention_days = 7
  }

  assert {
    condition     = aws_backup_vault_lock_configuration.this[0].min_retention_days == 7 && aws_backup_vault_lock_configuration.this[0].changeable_for_days == null
    error_message = "Without a grace period the lock must stay in governance mode (no changeable_for_days)."
  }
}

run "backup_vault_lock_rejects_retention_above_aws_maximum" {
  command = plan

  variables {
    backup_vault_lock_min_retention_days = 7
    backup_vault_lock_max_retention_days = 36501
  }

  expect_failures = [var.backup_vault_lock_max_retention_days]
}

run "backup_vault_policy_denies_tampering_except_exempt_roles" {
  command = plan

  variables {
    protect_backup_vault_recovery_points = true
    backup_vault_exempt_principal_arns   = ["arn:aws:iam::123456789012:role/terraform-deploy", "arn:aws:iam::123456789012:role/break-glass"]
  }

  assert {
    condition = (
      length(jsondecode(aws_backup_vault_policy.protect[0].policy).Statement) == 1 &&
      jsondecode(aws_backup_vault_policy.protect[0].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_backup_vault_policy.protect[0].policy).Statement[0].Principal.AWS == "*" &&
      toset(jsondecode(aws_backup_vault_policy.protect[0].policy).Statement[0].Action) == toset([
        "backup:DeleteRecoveryPoint",
        "backup:UpdateRecoveryPointLifecycle",
        "backup:DeleteBackupVault",
        "backup:PutBackupVaultAccessPolicy",
        "backup:DeleteBackupVaultAccessPolicy",
        "backup:PutBackupVaultLockConfiguration",
        "backup:DeleteBackupVaultLockConfiguration",
      ])
    )
    error_message = "The vault policy must deny every principal deleting recovery points, shortening their lifecycle, deleting the vault and changing its policy or lock (CP-9, SI-7)."
  }

  assert {
    condition     = toset(jsondecode(aws_backup_vault_policy.protect[0].policy).Statement[0].Condition.ArnNotLike["aws:PrincipalArn"]) == toset(var.backup_vault_exempt_principal_arns)
    error_message = "Exactly the exempt principals must be excluded by aws:PrincipalArn."
  }
}

run "backup_vault_policy_without_exemptions_is_rejected" {
  command = plan

  variables {
    protect_backup_vault_recovery_points = true
  }

  expect_failures = [var.protect_backup_vault_recovery_points]
}

run "backup_vault_policy_needs_the_vault" {
  command = plan

  variables {
    create_backup_vault                  = false
    protect_backup_vault_recovery_points = true
    backup_vault_exempt_principal_arns   = ["arn:aws:iam::123456789012:role/terraform-deploy"]
  }

  expect_failures = [var.protect_backup_vault_recovery_points]
}

run "backup_vault_exempt_principals_must_be_iam_arns" {
  command = plan

  variables {
    protect_backup_vault_recovery_points = true
    backup_vault_exempt_principal_arns   = ["terraform-deploy"]
  }

  expect_failures = [var.backup_vault_exempt_principal_arns]
}
