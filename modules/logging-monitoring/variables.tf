variable "cloudtrail_log_group_name" {
  type        = string
  description = "Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail)."
}

variable "expected_secret_readers" {
  type        = list(string)
  description = <<-DOC
    CloudTrail principal ARNs (userIdentity.arn) that normally read secrets
    and parameters, e.g. "arn:<partition>:sts::<account>:assumed-role/app-role/*".
    Each entry may contain one "*" wildcard. When non-empty, the module alarms
    on secretsmanager GetSecretValue and ssm GetParameter, GetParameters and
    GetParametersByPath by any other principal. Default empty creates no
    secret-read filter or alarm, because alerting on every read is too noisy.
  DOC
  default     = []

  validation {
    condition     = alltrue([for p in var.expected_secret_readers : !strcontains(p, "\"") && length(regexall("[*]", p)) <= 1])
    error_message = "Entries must not contain double quotes and may contain at most one * wildcard (CloudWatch Logs filter syntax)."
  }
}
