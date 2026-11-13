variable "environment" {
  description = "Environment identifier"
  type        = string
  default     = "fedramp"
}

variable "maintenance_window_cron" {
  description = "Cron expression for maintenance window (Default: Sunday at 02:00 AM UTC)"
  type        = string
  default     = "cron(0 2 ? * SUN *)"
}

variable "access_log_bucket" {
  type        = string
  default     = null
  description = <<-EOT
    Name of an existing S3 bucket to receive server access logs for the
    patch-log bucket (AU-2). Null leaves access logging off. S3 requires the
    destination to be in the same account and region, to allow
    logging.s3.amazonaws.com to write, to use SSE-S3 (not SSE-KMS), and to
    have no Object Lock default retention or Requester Pays. A central
    logging-account bucket can't be used directly; replicate from a local
    one instead.
  EOT
}
