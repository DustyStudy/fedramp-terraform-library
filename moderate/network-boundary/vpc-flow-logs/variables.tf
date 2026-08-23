variable "vpc_id" {
  type        = string
  description = "ID of an existing VPC to enable Flow Logs for."
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "S3 lifecycle retention in days for flow log records."
}
