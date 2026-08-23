variable "minimum_password_length" {
  type        = number
  default     = 14
  description = "Rev5 Moderate/High both expect a 14-character minimum."

  validation {
    condition     = var.minimum_password_length >= 14
    error_message = "minimum_password_length must be at least 14 for Rev5 Moderate/High."
  }
}

variable "max_password_age" {
  type        = number
  default     = 60
  description = "Days before a password must be rotated."
}

variable "password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Number of previous passwords remembered to prevent reuse."
}
