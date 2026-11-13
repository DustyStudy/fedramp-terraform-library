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

variable "additional_features" {
  type        = set(string)
  default     = ["RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS"]
  description = <<-EOT
    GuardDuty protections to turn on besides S3, EKS audit logs and EBS
    malware scanning: RDS_LOGIN_EVENTS (anomalous Aurora/RDS logins) and
    LAMBDA_NETWORK_LOGS (Lambda network activity). Each adds GuardDuty
    charges. To leave them off, set [] before the first apply: removing a
    feature later only drops it from Terraform state, it does not turn the
    protection off (do that in GuardDuty). A few commercial regions lack
    some protections (RDS Protection isn't in ap-east-2, for example); see
    the GuardDuty regions page and drop those features there. Runtime
    Monitoring is not offered here because it also needs its security agent
    managed.
  EOT

  validation {
    condition     = alltrue([for f in var.additional_features : contains(["RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS"], f)])
    error_message = "additional_features may contain only RDS_LOGIN_EVENTS and LAMBDA_NETWORK_LOGS."
  }
}
