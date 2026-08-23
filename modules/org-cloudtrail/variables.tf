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
