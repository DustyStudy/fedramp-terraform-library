variable "finding_publishing_frequency" {
  type        = string
  default     = "FIFTEEN_MINUTES"
  description = "How often GuardDuty publishes findings to CloudWatch Events."

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be one of FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "auto_enable" {
  type        = bool
  default     = true
  description = <<-EOT
    Deprecated: AWS provider v6 removed the auto_enable argument. Use
    auto_enable_organization_members instead. Kept so existing callers
    still plan; false must be paired with auto_enable_organization_members
    = "NONE".
  EOT
}

variable "auto_enable_organization_members" {
  type        = string
  default     = "NEW"
  description = "GuardDuty auto-enablement for member accounts: NEW (accounts that join later; matches the old auto_enable = true behavior), ALL (existing members too), or NONE."

  validation {
    condition     = contains(["ALL", "NEW", "NONE"], var.auto_enable_organization_members)
    error_message = "auto_enable_organization_members must be ALL, NEW, or NONE."
  }
}
