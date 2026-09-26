terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.65.1"
    }
  }
}

variable "target_ou_or_account_ids" {
  description = "Target OU or Account IDs"
  type        = list(string)
  default     = []
}

module "org_governance" {
  source = "../../modules/org-governance"

  backup_retention_days    = 1095
  target_ou_or_account_ids = var.target_ou_or_account_ids
}

provider "aws" {
  use_fips_endpoint = var.use_fips_endpoint
}

variable "use_fips_endpoint" {
  description = <<-EOT
    Send all AWS API calls to FIPS 140 validated endpoints (default true).
    FedRAMP CMU-CSO-UVM: validated crypto is a MUST for Class D and a SHOULD
    for Class C. Every service this library calls has FIPS endpoints in the
    US commercial regions and GovCloud (https://aws.amazon.com/compliance/fips/).
    Set false only for a region without them.
  EOT
  type        = bool
  default     = true
}
