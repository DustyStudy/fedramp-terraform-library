variable "unused_access_age" {
  type        = number
  default     = 90
  description = "Days of inactivity before Access Analyzer flags a permission as unused (supports AC-2(3), periodic account review)."
}

variable "analyzer_type" {
  type        = string
  default     = "ACCOUNT"
  description = "Use ORGANIZATION if deploying from the delegated Access Analyzer administrator account to cover all member accounts; ACCOUNT for a single-account deployment."

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.analyzer_type)
    error_message = "analyzer_type must be ACCOUNT or ORGANIZATION."
  }
}

variable "root_usage_alert_topic_name" {
  type    = string
  default = "root-account-usage-alerts"
}

variable "allow_password_change_without_mfa" {
  type        = bool
  default     = false
  description = "Exempt iam:ChangePassword and iam:GetAccountPasswordPolicy from the require-MFA deny, so a user created with a forced password reset (or whose password expired) can set a password at sign-in before registering MFA. Off by default because AWS advises against it; while off, such a user cannot sign in, so create users without a forced reset."
}

variable "developer_role_path" {
  type        = string
  default     = "/developer/"
  description = "IAM path of the roles a principal under the developer boundary may pass to Lambda. Every role under this path is one a developer's function can run as, so keep the path for roles meant for that."

  validation {
    condition     = can(regex("^/([!-~]+/)+$", var.developer_role_path))
    error_message = "developer_role_path must begin and end with / and name at least one path segment, e.g. /developer/. A bare / would let the boundary pass every role in the account."
  }
}
