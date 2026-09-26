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

resource "aws_ebs_default_kms_key" "this" {
  count   = var.kms_key_arn != "" ? 1 : 0
  key_arn = var.kms_key_arn
}

# IAM password policy — NIST SP 800-63B-4 defaults (see modules/iam-password-policy for rationale)
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

data "aws_iam_policy_document" "backup_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  count = var.create_backup_vault && var.backup_vault_kms_key_arn == "" ? 1 : 0

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
  count                   = var.create_backup_vault && var.backup_vault_kms_key_arn == "" ? 1 : 0
  description             = "CMK for the AWS Backup vault ${var.backup_vault_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.backup_kms[0].json
}

resource "aws_backup_vault" "this" {
  count       = var.create_backup_vault ? 1 : 0
  name        = var.backup_vault_name
  kms_key_arn = var.backup_vault_kms_key_arn != "" ? var.backup_vault_kms_key_arn : aws_kms_key.backup[0].arn
}
