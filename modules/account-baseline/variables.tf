variable "kms_key_arn" {
  description = "Optional custom KMS Key ARN to use for default EBS encryption."
  type        = string
  default     = ""
}

variable "minimum_password_length" {
  description = "Minimum password length for local IAM users (FedRAMP requires >= 14)."
  type        = number
  default     = 14
}

variable "max_password_age" {
  description = "Number of days before passwords expire (FedRAMP requires <= 60 or 90 days)."
  type        = number
  default     = 60
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to block reuse (FedRAMP requires >= 24)."
  type        = number
  default     = 24
}

variable "manage_default_vpc" {
  description = "Whether to adopt and restrict default VPC security groups."
  type        = bool
  default     = true
}
