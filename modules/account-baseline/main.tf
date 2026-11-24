# S3 Account-Level Public Access Block
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# EBS Default Encryption with KMS
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# The default EBS key is always a CMK: the module's own unless the caller
# supplies kms_key_arn. Without this resource the account falls back to aws/ebs.
resource "aws_ebs_default_kms_key" "this" {
  key_arn = local.create_ebs_kms_key ? aws_kms_key.ebs[0].arn : var.kms_key_arn

  lifecycle {
    precondition {
      condition     = local.create_ebs_kms_key || var.kms_key_arn != ""
      error_message = "set_ebs_default_kms_key = true requires kms_key_arn; without a key the account would use the AWS-managed aws/ebs key."
    }
  }
}

# Auto Scaling's service-linked role has no KMS permissions of its own, so the
# key policy must grant it or every Auto Scaling launch (EKS managed node
# groups, ECS capacity providers) fails with Client.InternalError. A key policy
# naming a principal that does not exist is rejected, and the role exists only
# after the account's first Auto Scaling group, so look it up (the plural data
# source returns an empty set instead of failing) and grant it when present.
data "aws_iam_roles" "autoscaling" {
  count       = local.create_ebs_kms_key && var.ebs_kms_key_grant_autoscaling ? 1 : 0
  name_regex  = "^AWSServiceRoleForAutoScaling$"
  path_prefix = "/aws-service-role/autoscaling.amazonaws.com/"
}

locals {
  # A key created in the same plan has an unknown ARN, so callers that create
  # their own key pass set_ebs_default_kms_key = true instead of relying on
  # the comparison.
  create_ebs_kms_key = var.set_ebs_default_kms_key == true ? false : var.kms_key_arn == ""

  ebs_kms_autoscaling_role_arns = sort(flatten(data.aws_iam_roles.autoscaling[*].arns))
}

data "aws_iam_policy_document" "ebs_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  count = local.create_ebs_kms_key ? 1 : 0

  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # The two statements AWS documents for Auto Scaling with a customer managed key:
  # https://docs.aws.amazon.com/autoscaling/ec2/userguide/key-policy-requirements-EBS-encryption.html
  dynamic "statement" {
    for_each = length(local.ebs_kms_autoscaling_role_arns) > 0 ? [1] : []
    content {
      sid    = "AllowAutoScalingUseOfTheKey"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = local.ebs_kms_autoscaling_role_arns
      }
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = length(local.ebs_kms_autoscaling_role_arns) > 0 ? [1] : []
    content {
      sid    = "AllowAutoScalingAttachmentOfPersistentResources"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = local.ebs_kms_autoscaling_role_arns
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "ebs" {
  count                   = local.create_ebs_kms_key ? 1 : 0
  description             = "CMK for account default EBS encryption"
  deletion_window_in_days = var.ebs_kms_key_deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ebs_kms[0].json
}

# IAM password policy — NIST SP 800-63B-4 defaults (see modules/iam-password-policy for rationale)
# Trivy AWS-0058..0061 require composition rules (CIS-era); NIST SP 800-63B-4, cited by
# FedRAMP IA-5 guidance, says verifiers SHALL NOT impose them. Opt in via require_* variables.
#trivy:ignore:AVD-AWS-0058 trivy:ignore:AVD-AWS-0059 trivy:ignore:AVD-AWS-0060 trivy:ignore:AVD-AWS-0061
resource "aws_iam_account_password_policy" "strict" {
  #checkov:skip=CKV_AWS_9:NIST SP 800-63B-4 (cited by FedRAMP IA-5 guidance) says verifiers SHALL NOT require periodic password changes; expiry is opt-in via max_password_age
  #checkov:skip=CKV_AWS_11:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_lowercase_characters
  #checkov:skip=CKV_AWS_12:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_numbers
  #checkov:skip=CKV_AWS_14:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_symbols
  #checkov:skip=CKV_AWS_15:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_uppercase_characters
  minimum_password_length        = var.minimum_password_length
  require_lowercase_characters   = var.require_lowercase_characters
  require_numbers                = var.require_numbers
  require_uppercase_characters   = var.require_uppercase_characters
  require_symbols                = var.require_symbols
  allow_users_to_change_password = true
  max_password_age               = var.max_password_age
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false
}

# Manage Default VPC / Subnets (Adopt and Restrict)
# The default VPC is adopted only so its default security group can be locked
# down below; nothing is deployed into it, so "default VPC in use" and "no flow
# logs" do not apply. Workload VPCs get flow logs from their own module.
#trivy:ignore:AVD-AWS-0101
#trivy:ignore:AVD-AWS-0178
resource "aws_default_vpc" "default" {
  #checkov:skip=CKV_AWS_148:Adopting default VPC to explicitly close all ingress/egress rules via default security group
  count = var.manage_default_vpc ? 1 : 0

  tags = {
    Name = "Default VPC (Do Not Use - FedRAMP Baseline)"
  }
}

resource "aws_default_security_group" "default" {
  count  = var.manage_default_vpc ? 1 : 0
  vpc_id = aws_default_vpc.default[0].id

  ingress = []
  egress  = []

  tags = {
    Name = "Default SG (Restricted - FedRAMP Baseline)"
  }
}

# AWS Backup vault targeted by modules/org-governance's backup policy (CP-9).
# The org policy runs backups into this vault by name, so it must exist in every
# member account and in every region listed in that policy's backup_regions
# (deploy this module once per region). Encrypted with a dedicated CMK unless
# backup_vault_kms_key_arn is supplied.
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  # As with set_ebs_default_kms_key: a key created in the same plan has an
  # unknown ARN, so the caller can say outright that it supplies the key.
  create_backup_kms_key = var.create_backup_vault && (var.create_backup_vault_kms_key != null ? var.create_backup_vault_kms_key : var.backup_vault_kms_key_arn == "")
}

data "aws_iam_policy_document" "backup_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  count = local.create_backup_kms_key ? 1 : 0

  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "backup" {
  count                   = local.create_backup_kms_key ? 1 : 0
  description             = "CMK for the AWS Backup vault ${var.backup_vault_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.backup_kms[0].json
}

resource "aws_backup_vault" "this" {
  count       = var.create_backup_vault ? 1 : 0
  name        = var.backup_vault_name
  kms_key_arn = local.create_backup_kms_key ? aws_kms_key.backup[0].arn : var.backup_vault_kms_key_arn

  lifecycle {
    precondition {
      condition     = local.create_backup_kms_key || var.backup_vault_kms_key_arn != ""
      error_message = "create_backup_vault_kms_key = false requires backup_vault_kms_key_arn; without a key the vault would use the AWS-managed one."
    }
  }
}

# The role the org backup policy names; see var.create_backup_service_role.
resource "aws_iam_role" "backup" {
  count = var.create_backup_service_role ? 1 : 0
  name  = "AWSBackupDefaultServiceRole"
  path  = "/service-role/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each   = var.create_backup_service_role ? toset(["AWSBackupServiceRolePolicyForBackup", "AWSBackupServiceRolePolicyForRestores"]) : toset([])
  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/${each.key}"
}

# --- Backup vault immutability (CP-9, CP-10, SI-7) ---
# Ransomware operators destroy backups before encrypting: Amazon's 2026-02-20
# report on the FortiGate campaign describes the actor going after Veeam backup
# servers as a precursor to ransomware. The org backup policy only sets a
# schedule and retention; without a lock, anyone with backup:DeleteRecoveryPoint
# in the account can delete every recovery point. Both controls below are
# opt-in because they can stop legitimate deletes and, in compliance mode,
# cannot be undone.

resource "aws_backup_vault_lock_configuration" "this" {
  count = var.create_backup_vault && var.backup_vault_lock_min_retention_days != null ? 1 : 0

  backup_vault_name   = aws_backup_vault.this[0].name
  min_retention_days  = var.backup_vault_lock_min_retention_days
  max_retention_days  = var.backup_vault_lock_max_retention_days
  changeable_for_days = var.backup_vault_lock_changeable_for_days
}

data "aws_iam_policy_document" "backup_vault_protect" {
  count = var.create_backup_vault && var.protect_backup_vault_recovery_points ? 1 : 0

  statement {
    sid    = "DenyRecoveryPointAndVaultTampering"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "backup:DeleteRecoveryPoint",
      "backup:UpdateRecoveryPointLifecycle",
      "backup:DeleteBackupVault",
      "backup:PutBackupVaultAccessPolicy",
      "backup:DeleteBackupVaultAccessPolicy",
      "backup:PutBackupVaultLockConfiguration",
      "backup:DeleteBackupVaultLockConfiguration",
    ]
    # A vault access policy is scoped to its own vault, so "*" here means this
    # vault and its recovery points only.
    resources = ["*"]

    dynamic "condition" {
      for_each = length(var.backup_vault_exempt_principal_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.backup_vault_exempt_principal_arns
      }
    }
  }
}

resource "aws_backup_vault_policy" "protect" {
  count = var.create_backup_vault && var.protect_backup_vault_recovery_points ? 1 : 0

  backup_vault_name = aws_backup_vault.this[0].name
  policy            = data.aws_iam_policy_document.backup_vault_protect[0].json
}
