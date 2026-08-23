terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
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

  backup_retention_days    = 365
  target_ou_or_account_ids = var.target_ou_or_account_ids
}
