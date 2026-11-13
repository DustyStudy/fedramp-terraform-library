variable "auto_enable_standards" {
  type        = bool
  default     = true
  description = "Automatically enable default security standards for new accounts joining the organization."
}

variable "enable_nist_800_53" {
  type        = bool
  default     = true
  description = "Subscribe this account to the NIST SP 800-53 Rev5 standard, the control catalog FedRAMP is built on."
}

variable "enable_finding_aggregator" {
  type        = bool
  default     = false
  description = "Make this region the Security Hub aggregation region, collecting findings from all regions. Set true in exactly one region of the delegated admin account."
}
