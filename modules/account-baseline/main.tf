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

# FedRAMP Compliant IAM Password Policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = var.minimum_password_length
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
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
