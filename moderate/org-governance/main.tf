terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.66.1"
    }
  }
}

variable "target_ou_or_account_ids" {
  description = "Target OU or Account IDs"
  type        = list(string)
  default     = []
}

data "aws_partition" "current" {}

module "org_governance" {
  source = "../../modules/org-governance"

  backup_retention_days    = 365
  target_ou_or_account_ids = var.target_ou_or_account_ids
  backup_regions           = data.aws_partition.current.partition == "aws-us-gov" ? ["us-gov-west-1", "us-gov-east-1"] : ["us-east-1", "us-west-2"]
}
