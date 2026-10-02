variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "rds-access-auditor"
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

variable "regions" {
  type        = list(string)
  description = "Regions to audit RDS databases in. Empty means the region the module is deployed in. IAM roles are global and always audited."
  default     = []

  validation {
    condition     = alltrue([for r in var.regions : can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", r))])
    error_message = "Each region must look like us-east-1 or us-gov-west-1."
  }
}

variable "member_role_name" {
  type        = string
  description = <<-EOT
    Name of a read-only role to assume in every other active account of
    the organization. Empty scans only the account the module is deployed
    in. The role must trust this module's Lambda role (output
    lambda_role_arn) and allow the actions in output
    member_role_policy_json.
  EOT
  default     = ""

  validation {
    condition     = can(regex("^[a-zA-Z0-9_+=,.@-]{0,64}$", var.member_role_name))
    error_message = "member_role_name must be a role name (not an ARN), up to 64 characters."
  }
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
