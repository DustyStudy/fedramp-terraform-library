variable "kms_key_arn" {
  description = "Existing CMK ARN to use as the default EBS encryption key. Empty creates a dedicated CMK with rotation enabled. A key you bring needs its own key policy statements for the Auto Scaling service-linked role (see README)."
  type        = string
  default     = ""
}

variable "set_ebs_default_kms_key" {
  description = "Leave null to decide from kms_key_arn. Set true when kms_key_arn is a key created in the same plan, where its ARN is not known yet; the module then creates no key of its own."
  type        = bool
  default     = null
}

variable "ebs_kms_key_deletion_window_in_days" {
  description = "Waiting period (7-30 days) before the module-created EBS CMK is deleted after it is destroyed."
  type        = number
  default     = 30

  validation {
    condition     = var.ebs_kms_key_deletion_window_in_days >= 7 && var.ebs_kms_key_deletion_window_in_days <= 30
    error_message = "ebs_kms_key_deletion_window_in_days must be between 7 and 30."
  }
}

variable "ebs_kms_key_grant_autoscaling" {
  description = <<-EOT
    Grant the Auto Scaling service-linked role (AWSServiceRoleForAutoScaling)
    use of the module-created EBS CMK when that role exists in the account.
    Without the grant, Auto Scaling launches (EKS managed node groups, ECS
    capacity providers) fail with Client.InternalError. AWS creates the role
    with the account's first Auto Scaling group; in an account that does not
    have it yet, create it first or re-apply this module afterwards (see
    README). Needs iam:ListRoles. Ignored when you supply kms_key_arn.
  EOT
  type        = bool
  default     = true
}

variable "minimum_password_length" {
  description = "Minimum password length. NIST SP 800-63B-4: at least 15 for single-factor passwords; 8 only when always used with MFA. FedRAMP assigns no separate value."
  type        = number
  default     = 15
}

variable "max_password_age" {
  description = "Days before a password must be changed; 0 disables expiry. NIST SP 800-63B-4 says verifiers SHALL NOT require periodic changes, so 0 is the default. Set a value only if your own policy requires rotation."
  type        = number
  default     = 0
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords remembered to prevent reuse (organization-defined; FedRAMP assigns no value)."
  type        = number
  default     = 24
}

variable "manage_default_vpc" {
  description = "Whether to adopt and restrict default VPC security groups."
  type        = bool
  default     = true
}

variable "require_uppercase_characters" {
  type        = bool
  default     = false
  description = "Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules."
}

variable "require_lowercase_characters" {
  type        = bool
  default     = false
  description = "Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules."
}

variable "require_numbers" {
  type        = bool
  default     = false
  description = "Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules."
}

variable "require_symbols" {
  type        = bool
  default     = false
  description = "Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules."
}

variable "create_backup_vault" {
  description = "Create the AWS Backup vault that modules/org-governance's backup policy targets. Deploy once per region listed in that policy's backup_regions."
  type        = bool
  default     = true
}

variable "backup_vault_name" {
  description = "Backup vault name; must match org-governance's backup_vault_name."
  type        = string
  default     = "FedRAMPComplianceVault"
}

variable "backup_vault_kms_key_arn" {
  description = "Optional existing CMK ARN for the backup vault. Empty creates a dedicated CMK with rotation enabled."
  type        = string
  default     = ""
}

variable "create_backup_vault_kms_key" {
  description = "Create the dedicated backup vault CMK. Leave null to decide from backup_vault_kms_key_arn; set false when that key is created in the same plan, where its ARN is not known yet."
  type        = bool
  default     = null
}

variable "create_backup_service_role" {
  description = <<-EOT
    Create service-role/AWSBackupDefaultServiceRole, the role
    modules/org-governance's backup policy runs jobs as. AWS creates it only
    the first time someone opens the Backup console, so new accounts lack it
    and every scheduled job fails. The role is global: when you deploy this
    module in more than one region, set this true in exactly one of them.
    Set false if the role already exists in the account.
  EOT
  type        = bool
  default     = true
}
