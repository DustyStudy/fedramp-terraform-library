# Live proof stack for the two auditors that only work from the organization
# management account (or a delegated administrator): they read IAM Identity
# Center and an organization-wide CloudTrail Lake event data store.
#
# Apply in the Identity Center home region, invoke both Lambdas, destroy.
# The event data store has termination protection; see docs/PROOF.md.

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

module "stale_account_detector" {
  source      = "../../modules/stale-account-detector"
  name_prefix = "ftlproof-stale-accounts"

  reserved_concurrent_executions = -1

  # The data store is minutes old when the Lambda runs, so one day of
  # lookback is all it can answer for.
  activity_lookback_days          = 1
  event_data_store_retention_days = 7
}

output "identity_center_auditor_lambda" {
  description = "Function to invoke for the Identity Center audit."
  value       = module.identity_center_access_auditor.lambda_function_arn
}

output "stale_account_detector_lambda" {
  description = "Function to invoke for the stale-account report."
  value       = module.stale_account_detector.lambda_function_arn
}

output "event_data_store_arn" {
  description = "Event data store to take termination protection off before destroy."
  value       = module.stale_account_detector.event_data_store_arn
}
