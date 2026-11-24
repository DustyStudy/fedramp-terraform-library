# Live proof for release 4.1.0, part B: account-baseline's backup vault with
# Vault Lock (governance mode) and the vault access policy that denies
# deleting recovery points to everyone but the exempt principals.
#
# account-baseline also manages account-wide settings (default EBS key, S3
# account public access block, password policy, default VPC). This stack must
# leave those alone, so it is ALWAYS planned with the -target list in
# ../README.md. As a trip-wire, set_ebs_default_kms_key = true with no
# kms_key_arn fails the module's own precondition, so a plan without
# -target errors instead of offering to change the account.

terraform {
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
  # false: with true the provider also sends the SSO credential call to
  # portal.sso-fips.<region>, which does not exist. The modules under test
  # still default their own Lambdas to FIPS endpoints.
  use_fips_endpoint = false

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "region" {
  description = "Region for the proof stack."
  type        = string
  default     = "us-east-1"
}

variable "profile" {
  description = "AWS CLI profile of the sandbox member account."
  type        = string
  default     = "AdministratorAccess-264524063329"
}

variable "create_backup_service_role" {
  description = "Set false if service-role/AWSBackupDefaultServiceRole already exists in the account; the two aws_iam_role* targets then match nothing."
  type        = bool
  default     = true
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# The IAM role behind the caller's session, path included. Exempting it by
# its exact ARN means the apply cannot lock its own caller out of the vault
# policy if the wildcard below does not match (Identity Center outside
# us-east-1 puts the region in the role path).
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  name       = "ftl410"
  partition  = data.aws_partition.current.partition
  account    = data.aws_caller_identity.current.account_id
  vault_name = "${local.name}-vault"
  vault_arn  = "arn:${local.partition}:backup:${var.region}:${local.account}:backup-vault:${local.vault_name}"
}

# --- Module under test (backup resources only, by -target) --------------------

module "account_baseline" {
  source = "../../../modules/account-baseline"

  create_backup_vault                   = true
  backup_vault_name                     = local.vault_name
  create_backup_service_role            = var.create_backup_service_role
  backup_vault_lock_min_retention_days  = 1
  backup_vault_lock_changeable_for_days = null # governance mode
  protect_backup_vault_recovery_points  = true
  backup_vault_exempt_principal_arns = [
    "arn:${local.partition}:iam::${local.account}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_*",
    data.aws_iam_session_context.current.issuer_arn,
  ]

  # Trip-wire and blast-radius limit for a plan that forgets -target.
  set_ebs_default_kms_key = true
  manage_default_vpc      = false
}

# --- Fixtures -----------------------------------------------------------------

resource "aws_dynamodb_table" "backup_src" {
  #checkov:skip=CKV_AWS_28: Fixture. One item, lives for one proof run.
  #checkov:skip=CKV_AWS_119: Fixture. One item, lives for one proof run.
  #checkov:skip=CKV2_AWS_16: Fixture. On-demand table.
  name         = "${local.name}-backup-src"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_table_item" "backup_src" {
  table_name = aws_dynamodb_table.backup_src.name
  hash_key   = aws_dynamodb_table.backup_src.hash_key
  item       = jsonencode({ id = { S = "ftl410" } })
}

# Not an exempt principal. Its IAM policy allows the three calls, so a denial
# can only come from the vault access policy. No reference to the module on
# purpose: a dependency would pull the whole module into a -target apply.
resource "aws_iam_role" "backup_deleter" {
  name = "${local.name}-backup-deleter"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "backup_deleter" {
  #checkov:skip=CKV_AWS_290: Fixture. The allow is the point: the vault policy must still deny.
  #checkov:skip=CKV_AWS_355: Fixture. Recovery point ARNs are not known until a backup has run.
  name = "${local.name}-backup-deleter"
  role = aws_iam_role.backup_deleter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "backup:DeleteBackupVault"
        Resource = local.vault_arn
      },
    ]
  })
}

# --- What probe.py reads ------------------------------------------------------

# Built from names and targeted fixtures only: an output that depends on an
# untargeted resource is left out of a -target apply.
output "probe" {
  description = "Names and ARNs ../probe.py needs."
  value = {
    region           = var.region
    profile          = var.profile
    vault_name       = local.vault_name
    backup_role_arn  = "arn:${local.partition}:iam::${local.account}:role/service-role/AWSBackupDefaultServiceRole"
    table_arn        = aws_dynamodb_table.backup_src.arn
    deleter_role_arn = aws_iam_role.backup_deleter.arn
  }
}
