variable "policy_name" {
  description = "Name of the SCP"
  type        = string
  default     = "fedramp-authorization-boundary-scp"
}

variable "approved_regions" {
  description = "List of approved FedRAMP regions"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "target_ou_or_account_ids" {
  description = "List of Organizational Units or Account IDs to attach this SCP"
  type        = list(string)
  default     = []
}
