variable "kms_key_arn" {
  description = "Optional custom KMS Key ARN to use for default EBS encryption."
  type        = string
  default     = ""
}

variable "set_ebs_default_kms_key" {
  description = "Set kms_key_arn as the default EBS key. Leave null to decide from kms_key_arn; set true when the key is created in the same plan, where its ARN is not known yet."
  type        = bool
  default     = null
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
