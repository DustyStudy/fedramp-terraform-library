variable "organization_id" {
  type        = string
  description = "AWS Organizations ID (e.g. o-xxxxxxxxxx). Required for the bucket policy trust condition."

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must match the AWS Organizations ID format, e.g. o-xxxxxxxxxx."
  }
}

variable "trail_name" {
  type        = string
  default     = "org-security-trail"
  description = "Name for the organization trail."

  validation {
    condition     = !can(regex("\\.", var.trail_name))
    error_message = "trail_name must not contain dots: S3 FIPS endpoints are virtual-hosted and do not support dotted bucket names."
  }
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = <<-EOT
    CloudWatch Logs retention. Moderate baseline typically expects >= 90
    days readily available plus 1 year total; High baseline commonly
    expects 3+ years total retention — confirm against your SSP.
  EOT
}

variable "s3_log_retention_days" {
  type        = number
  default     = 2555
  description = "S3 lifecycle retention in days for the long-term log archive (default ~7 years). Adjust to your organization's records retention schedule."
}

variable "object_lock_retention_days" {
  type        = number
  default     = null
  description = <<-EOT
    Turn on S3 Object Lock for the trail bucket with this default retention,
    so no one can delete or overwrite a log file before it ends (AU-9). Null
    (the default) leaves Object Lock off. Must not exceed
    s3_log_retention_days. Object Lock can't be turned off once enabled.
  EOT

  validation {
    condition     = var.object_lock_retention_days == null || try(var.object_lock_retention_days >= 1, false)
    error_message = "object_lock_retention_days must be at least 1, or null to leave Object Lock off."
  }
}

variable "object_lock_mode" {
  type        = string
  default     = "GOVERNANCE"
  description = "GOVERNANCE lets principals with s3:BypassGovernanceRetention remove a lock; COMPLIANCE lets no one, including root, until retention ends."

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "log_s3_data_events" {
  type        = bool
  default     = true
  description = <<-EOT
    Record S3 object-level (data) events for every bucket in the
    organization (AU-2, AU-12). This can cost a lot in busy accounts; set
    false to log management events only and add targeted data events in a
    separate trail.
  EOT
}
