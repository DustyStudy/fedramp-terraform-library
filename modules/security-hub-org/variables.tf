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

variable "delegated_admin_account_id" {
  type        = string
  default     = null
  description = <<-EOT
    Account ID of the Security Hub delegated administrator. Pass
    aws_securityhub_organization_admin_account.<name>.id when the same root
    designates it: the organization configuration then waits for the
    designation, and the plan fails if this module's provider is not that
    account. Security Hub itself is still enabled first, which the
    designation needs to not collide with (designating an account enables
    Security Hub in it). null skips both.
  EOT
}
