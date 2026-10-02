variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "identity-center-access-auditor"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression controlling how often the audit runs."
  default     = "rate(1 day)"
}

variable "sensitive_wildcard_services" {
  type        = list(string)
  description = "IAM service prefixes where \"<service>:*\" combined with Resource \"*\" in a permission set's inline policy is flagged as over-broad."
  default     = ["iam", "ec2", "s3", "kms", "organizations", "sts"]
}

variable "escalation_actions" {
  type        = list(string)
  description = <<-EOT
    IAM and Identity Center actions flagged when a permission set's inline
    policy allows them on a resource that contains "*". Action patterns in
    the policy (such as "iam:Put*") are matched against this list. Leave
    null for the Lambda's built-in list: policy edits, policy versions,
    trust policy edits, permissions boundary changes, access keys and
    login profiles, iam:PassRole, and permission set changes.
  EOT
  default     = null
}

variable "flag_direct_user_assignments" {
  type        = bool
  description = <<-EOT
    Flag account assignments made directly to a user rather than a
    group. Assignments should generally flow through groups so access
    can be reasoned about and rotated as people change teams.
  EOT
  default     = true
}

variable "report_unused_permission_sets" {
  type        = bool
  description = <<-EOT
    Include permission sets provisioned to zero accounts as an
    informational addendum whenever the audit already has other
    findings to report. This never triggers a notification by itself.
  EOT
  default     = true
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
