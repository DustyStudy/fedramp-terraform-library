variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "stale-account-detector"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic for the stale-account report. Leave empty to skip."
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression controlling how often the scan runs."
  default     = "rate(7 days)"
}

variable "excluded_account_ids" {
  type        = list(string)
  description = "Account IDs to always skip (break-glass accounts, intentionally idle sandboxes, log-archive accounts, etc.)."
  default     = []
}

variable "exempt_tag_key" {
  type        = string
  description = "Optional AWS Organizations account tag key. Accounts carrying this tag are skipped entirely. Leave empty to check every account."
  default     = ""
}

variable "exempt_tag_value" {
  type        = string
  description = "Optional value exempt_tag_key must match. Leave empty to exempt on the tag key's presence alone (any value)."
  default     = ""
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
    reservation.
  EOT
  default     = 1

  validation {
    condition     = var.reserved_concurrent_executions >= -1
    error_message = "reserved_concurrent_executions must be -1 (unreserved) or a non-negative number."
  }
}

variable "inactivity_days" {
  type        = number
  description = <<-EOT
    Days without use after which an identity or account is reported.
    1 through 90: CloudTrail event history, which the Identity Center
    checks read, goes back 90 days. Use 35 for FedRAMP High.
  EOT
  default     = 90

  validation {
    condition     = var.inactivity_days >= 1 && var.inactivity_days <= 90 && floor(var.inactivity_days) == var.inactivity_days
    error_message = "inactivity_days must be a whole number from 1 to 90."
  }
}

variable "member_role_name" {
  type        = string
  description = <<-EOT
    Name of the read-only role the Lambda assumes in each member account.
    Create it in every account with the member_role_policy_json output and
    a trust policy for the lambda_role_arn output. Empty reads only this
    account's IAM, and the report says the member accounts were not checked.
  EOT
  default     = ""

  validation {
    condition     = can(regex("^[\\w+=,.@-]{0,64}$", var.member_role_name))
    error_message = "member_role_name must be a role name, not an ARN or a path."
  }
}

variable "ignored_role_names" {
  type        = list(string)
  description = <<-EOT
    Roles whose use does not count as account activity, such as scanner
    roles that run in every account. The member role is always ignored.
    These roles are still reported if they themselves go unused.
  EOT
  default     = []
}
