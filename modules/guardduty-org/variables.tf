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
    Automatically enable GuardDuty for new accounts joining the
    organization. This module uses the long-standing `auto_enable`
    boolean argument. The underlying GuardDuty API also supports a
    newer, more granular `AutoEnableOrganizationMembers` setting
    (NEW/ALL/NONE) — if your AWS provider version exposes an equivalent
    argument on aws_guardduty_organization_configuration, check current
    provider docs and consider using it instead for finer control over
    existing vs. new member accounts.
  EOT
}
