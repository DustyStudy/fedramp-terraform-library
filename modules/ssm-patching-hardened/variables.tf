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
    patch-log bucket (AU-2). Null (the default) makes the module create its
    own access-log bucket. S3 requires the destination to be in the same
    account and region, to allow logging.s3.amazonaws.com to write, to use
    SSE-S3 (not SSE-KMS), and to have no Object Lock default retention or
    Requester Pays. A central logging-account bucket can't be used
    directly; replicate from a local one instead.
  EOT
}

variable "max_concurrency" {
  type        = string
  default     = "50%"
  description = "How many targets the patch task runs on at once, as a count (\"10\") or a percentage (\"50%\"). Lower it if the nodes patched together are each other's redundancy."

  validation {
    condition     = can(regex("^([1-9][0-9]*|[1-9][0-9]?%|100%)$", var.max_concurrency))
    error_message = "max_concurrency must be a positive count or a percentage from 1% to 100%."
  }
}

variable "max_errors" {
  type        = string
  default     = "10%"
  description = "How many targets may fail before the patch task stops sending the command to more, as a count (\"1\") or a percentage (\"10%\"). With \"0\" one unhealthy node stops patching for every node not yet started."

  validation {
    condition     = can(regex("^(0|[1-9][0-9]*|[0-9]%|[1-9][0-9]%|100%)$", var.max_errors))
    error_message = "max_errors must be a count or a percentage from 0% to 100%."
  }
}
