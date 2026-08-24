variable "policy_name" {
  description = "Name of the SCP"
  type        = string
  default     = "fedramp-authorization-boundary-scp"
}

variable "approved_regions" {
  description = <<-EOT
    List of approved FedRAMP regions. Defaults assume a standard AWS
    commercial deployment (us-east-1, us-west-2) — if deploying in AWS
    GovCloud, override with GovCloud region names (e.g. us-gov-west-1,
    us-gov-east-1) instead, since the two partitions don't share regions.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "target_ou_or_account_ids" {
  description = "List of Organizational Units or Account IDs to attach this SCP"
  type        = list(string)
  default     = []
}
