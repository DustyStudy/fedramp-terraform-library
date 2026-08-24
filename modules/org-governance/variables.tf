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

variable "backup_regions" {
  description = <<-EOT
    Regions the centralized backup plan replicates to. Defaults assume a
    standard AWS commercial deployment (us-east-1, us-west-2) — if
    deploying in AWS GovCloud, override with GovCloud region names
    (e.g. us-gov-west-1, us-gov-east-1) instead, since the two partitions
    don't share regions.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}
