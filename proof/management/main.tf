# Live proof stack for the two auditors that only work from the organization
# management account (or a delegated administrator): they read IAM Identity
# Center, CloudTrail event history and, through a member role, IAM in
# other accounts.
#
# Apply in the Identity Center home region, invoke both Lambdas, destroy.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.66.1"
    }
  }
}

provider "aws" {
  region            = var.region
  use_fips_endpoint = true

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "region" {
  description = "IAM Identity Center home region."
  type        = string
}

module "identity_center_access_auditor" {
  source      = "../../modules/identity-center-access-auditor"
  name_prefix = "ftlproof-idc-auditor"

  # The management account sits at the 10-execution Lambda quota floor in
  # this region, where any reservation is rejected.
  reserved_concurrent_executions = -1
}

output "identity_center_auditor_lambda" {
  description = "Function to invoke for the Identity Center audit."
  value       = module.identity_center_access_auditor.lambda_function_arn
}

module "stale_account_detector" {
  source      = "../../modules/stale-account-detector"
  name_prefix = "ftlproof-stale-accounts"

  reserved_concurrent_executions = -1

  # One day, so the organization's real identities produce findings
  # without waiting 90 days. A fixture cannot be made stale on demand,
  # because creation time counts as activity.
  inactivity_days    = 1
  member_role_name   = "ftlproof-stale-read"
  ignored_role_names = var.ignored_role_names
}

variable "ignored_role_names" {
  description = "Scanner roles that should not count as account activity."
  type        = list(string)
  default     = []
}

output "stale_account_detector_lambda" {
  description = "Function to invoke for the stale access report."
  value       = module.stale_account_detector.lambda_function_arn
}

output "stale_account_detector_role_arn" {
  description = "Role the member-account read role must trust."
  value       = module.stale_account_detector.lambda_role_arn
}

output "member_role_policy_json" {
  description = "Policy for the member-account read role."
  value       = module.stale_account_detector.member_role_policy_json
}
