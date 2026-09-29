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

variable "require_imdsv2" {
  description = <<-EOT
    Add statements that deny launching an EC2 instance without IMDSv2
    (HttpTokens = required) and deny switching an instance back to IMDSv1.
    Off by default: turning it on breaks any launch template, AMI pipeline
    or tool that still sets HttpTokens to optional.
  EOT
  type        = bool
  default     = false
}
