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
