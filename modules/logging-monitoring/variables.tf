variable "cloudtrail_log_group_name" {
  type        = string
  description = "Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail)."
}

variable "expected_secret_readers" {
  type        = list(string)
  description = <<-DOC
    CloudTrail principal ARNs (userIdentity.arn) that normally read secrets
    and parameters, e.g. "arn:<partition>:sts::<account>:assumed-role/app-role/*".
    Each entry may contain one "*" wildcard. For a role, use that assumed-role
    session form, not the IAM role ARN, which never appears in userIdentity.arn.
    When non-empty, the module alarms on secretsmanager GetSecretValue and ssm
    GetParameter, GetParameters, GetParametersByPath and GetParameterHistory by
    any other principal. The generated filter pattern must fit CloudWatch
    Logs' 1024-character limit, so prefer wildcards over long lists. Default
    empty creates no secret-read filter or alarm, because alerting on every
    read is too noisy.
  DOC
  default     = []

  validation {
    condition     = alltrue([for p in var.expected_secret_readers : !strcontains(p, "\"") && length(regexall("[*]", p)) <= 1])
    error_message = "Entries must not contain double quotes and may contain at most one * wildcard (CloudWatch Logs filter syntax)."
  }

  validation {
    condition     = alltrue([for p in var.expected_secret_readers : !can(regex(":iam::[^:]*:role/", p))])
    error_message = "IAM role ARNs never match CloudTrail userIdentity.arn, so every read would alarm. Use the session form arn:<partition>:sts::<account>:assumed-role/<RoleName>/* instead."
  }
}
