variable "unused_access_age" {
  type        = number
  default     = 90
  description = "Days of inactivity before Access Analyzer flags a permission as unused (supports AC-2(3), periodic account review)."
}

variable "analyzer_type" {
  type        = string
  default     = "ACCOUNT"
  description = "Use ORGANIZATION if deploying from the delegated Access Analyzer administrator account to cover all member accounts; ACCOUNT for a single-account deployment."

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.analyzer_type)
    error_message = "analyzer_type must be ACCOUNT or ORGANIZATION."
  }
}

variable "root_usage_alert_topic_name" {
  type    = string
  default = "root-account-usage-alerts"
}
