variable "target_ou_or_account_ids" {
  description = "Target OU or Member Account IDs"
  type        = list(string)
  default     = []
}

module "org_scp_boundary" {
  source = "../../modules/org-scp-boundary"

  policy_name              = "fedramp-high-authorization-boundary"
  approved_regions         = ["us-east-1", "us-west-2"]
  target_ou_or_account_ids = var.target_ou_or_account_ids
}

provider "aws" {
  use_fips_endpoint = var.use_fips_endpoint
}

variable "use_fips_endpoint" {
  description = <<-EOT
    Send AWS API calls to FIPS 140 validated endpoints. Class D (formerly High)
    MUST use validated cryptographic modules under FedRAMP rule CMU-CSO-UVM.
    Every service this root calls has FIPS endpoints in US commercial regions
    and GovCloud (https://aws.amazon.com/compliance/fips/); set false only for
    a region without them.
  EOT
  type        = bool
  default     = true
}
