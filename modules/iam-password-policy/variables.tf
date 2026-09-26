variable "minimum_password_length" {
  type        = number
  default     = 15
  description = "Minimum password length. NIST SP 800-63B-4: at least 15 for single-factor passwords; 8 only when always used with MFA. FedRAMP assigns no separate value."

  validation {
    condition     = var.minimum_password_length >= 8
    error_message = "minimum_password_length must be at least 8 (NIST SP 800-63B-4 floor for MFA-only passwords; use 15+ for single-factor)."
  }
}

variable "max_password_age" {
  type        = number
  default     = 0
  description = "Days before a password must be changed; 0 disables expiry. NIST SP 800-63B-4 says verifiers SHALL NOT require periodic changes, so 0 is the default. Set a value only if your own policy requires rotation."
}

variable "password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Number of previous passwords remembered to prevent reuse (organization-defined; FedRAMP assigns no value)."
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
