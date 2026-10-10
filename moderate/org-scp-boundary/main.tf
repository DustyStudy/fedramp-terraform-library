variable "target_ou_or_account_ids" {
  description = "Target OU or Member Account IDs"
  type        = list(string)
  default     = []
}

data "aws_partition" "current" {}

module "org_scp_boundary" {
  source = "../../modules/org-scp-boundary"

  policy_name              = "fedramp-moderate-authorization-boundary"
  approved_regions         = data.aws_partition.current.partition == "aws-us-gov" ? ["us-gov-west-1", "us-gov-east-1"] : ["us-east-1", "us-west-2"]
  target_ou_or_account_ids = var.target_ou_or_account_ids
}
