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

variable "activity_lookback_days" {
  type        = number
  description = <<-EOT
    Accounts with no CloudTrail activity in this many days are reported
    as stale. Also bounds the CloudTrail Lake query window - keep this
    at or below the event data store's actual retention period.
  EOT
  default     = 90
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

variable "create_event_data_store" {
  type        = bool
  description = <<-EOT
    Create a new organization-wide CloudTrail Lake event data store
    (management events only, scoped to keep ingestion cost down). Set to
    false if you already have a suitable one and supply its ARN via
    existing_event_data_store_arn instead - CloudTrail Lake bills by
    ingestion volume, so avoid standing up a duplicate store just for
    this tool if one already exists.
  EOT
  default     = true
}

variable "existing_event_data_store_arn" {
  type        = string
  description = <<-EOT
    ARN of an existing organization-wide CloudTrail Lake event data
    store to query instead of creating a new one. Required if
    create_event_data_store is false. It must be organization-enabled
    and include management events, or this tool won't see activity from
    member accounts.
  EOT
  default     = ""
}

variable "event_data_store_retention_days" {
  type        = number
  description = <<-EOT
    Retention period (days) for the event data store this module
    creates. Ignored if create_event_data_store is false. Minimum
    supported by CloudTrail Lake is 7 days; keep this comfortably above
    activity_lookback_days.
  EOT
  default     = 92
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
