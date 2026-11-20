variable "cloudtrail_log_group_name" {
  type        = string
  description = "Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail). It must be in the account and region this module is deployed in."
}

variable "enabled" {
  type        = bool
  description = <<-EOT
    Run the detector on its schedule. Default false: everything is created
    but the EventBridge rule is DISABLED, so nothing is queried and nothing
    alerts. Turn it on per account after a tuning period.
  EOT
  default     = false
}

variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "secret-access-burst-detector"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression controlling how often the detector runs. Keep the interval shorter than query_window_minutes so no events fall between runs."
  default     = "rate(15 minutes)"
}

variable "query_window_minutes" {
  type        = number
  description = "How far back each run looks. Denied calls and secret reads are correlated inside this window. A longer window scans more log data per run."
  default     = 30

  validation {
    condition     = var.query_window_minutes >= 1 && floor(var.query_window_minutes) == var.query_window_minutes
    error_message = "query_window_minutes must be a whole number of minutes, at least 1."
  }
}

variable "denied_call_threshold" {
  type        = number
  description = "Denied API calls (errorCode AccessDenied* or *UnauthorizedOperation) by one principal inside the window that make it a suspect. A suspect that also read a secret or parameter is reported."
  default     = 20

  validation {
    condition     = var.denied_call_threshold >= 1 && floor(var.denied_call_threshold) == var.denied_call_threshold
    error_message = "denied_call_threshold must be a whole number, at least 1."
  }
}

variable "ignored_principal_arns" {
  type        = list(string)
  description = <<-EOT
    CloudTrail principal ARNs (userIdentity.arn) never reported, for
    automation that is routinely denied and also reads secrets, e.g.
    "arn:<partition>:sts::<account>:assumed-role/inventory-scanner/*".
    "*" matches any run of characters. Keep the list short: an ignored
    principal whose credential is stolen is not detected.
  EOT
  default     = []
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}

variable "use_fips_endpoint" {
  type        = bool
  description = <<-EOT
    Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints
    (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider
    setting in this library's root configurations.
  EOT
  default     = true
}

variable "reserved_concurrent_executions" {
  type        = number
  description = <<-EOT
    Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at
    the 10-execution quota floor (new and sandbox accounts) reject any
    reservation. 0 is rejected because it throttles every run.
  EOT
  default     = 2

  validation {
    condition     = var.reserved_concurrent_executions == -1 || var.reserved_concurrent_executions >= 1
    error_message = "reserved_concurrent_executions must be -1 (unreserved) or at least 1; 0 would throttle every run."
  }
}
