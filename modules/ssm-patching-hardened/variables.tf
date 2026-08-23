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
