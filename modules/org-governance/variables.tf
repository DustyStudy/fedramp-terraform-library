variable "target_ou_or_account_ids" {
  description = "List of OUs or Account IDs to attach these policies to"
  type        = list(string)
  default     = []
}

variable "authorized_security_admin_arns" {
  description = "ARNs allowed to manage S3 Object Lock settings"
  type        = list(string)
  default     = []
}

variable "backup_retention_days" {
  description = "Number of days to retain backups (FedRAMP Moderate: 365, High: 1095+)"
  type        = number
  default     = 365
}
