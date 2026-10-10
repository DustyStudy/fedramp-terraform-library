variable "target_ou_or_account_ids" {
  description = "Target OU or Member Account IDs"
  type        = list(string)
  default     = []
}

data "aws_partition" "current" {}

module "org_scp_boundary" {
  source = "../../modules/org-scp-boundary"

  policy_name              = "fedramp-high-authorization-boundary"
  approved_regions         = data.aws_partition.current.partition == "aws-us-gov" ? ["us-gov-west-1", "us-gov-east-1"] : ["us-east-1", "us-west-2"]
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
