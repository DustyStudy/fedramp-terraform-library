variable "guardduty_severity_threshold" {
  type        = number
  default     = 7
  description = <<-EOT
    Minimum GuardDuty finding severity to route here (7.0+ is High per
    GuardDuty's severity scale; 4.0-6.9 is Medium, 0.1-3.9 is Low).
  EOT

  validation {
    condition     = var.guardduty_severity_threshold >= 0 && var.guardduty_severity_threshold <= 8.9
    error_message = "guardduty_severity_threshold must be between 0 and 8.9."
  }
}

variable "exclude_guardduty_from_securityhub" {
  type        = bool
  default     = true
  description = <<-EOT
    Leave GuardDuty findings out of the Security Hub rule, so a finding the
    GuardDuty rule already routed is not delivered a second time. Set false
    if Security Hub in this account and region aggregates findings from
    regions or accounts whose GuardDuty events do not reach this event bus;
    those would otherwise not be routed at all.
  EOT
}
