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
  description = <<-EOT
    Number of days to retain backups (and cross-region copies). FedRAMP assigns
    no CP-9 retention value: set this from your own contingency plan. AWS
    requires deletion at least 90 days after the day-30 cold-storage move.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = var.backup_retention_days >= 120
    error_message = "backup_retention_days must be >= 120 (cold storage at day 30 + AWS's 90-day cold-storage minimum)."
  }
}

variable "backup_vault_name" {
  description = <<-EOT
    Name of the AWS Backup vault the policy writes to. The vault must exist in
    every member account and every region in backup_regions before backups
    run: deploy modules/account-baseline (create_backup_vault = true, the
    default) per account and region, or create it another way.
  EOT
  type        = string
  default     = "FedRAMPComplianceVault"
}

variable "copy_destination_region" {
  description = <<-EOT
    Optional region to copy every backup to (same vault name, same member
    account). Empty string disables cross-region copies. The destination vault
    must exist in that region in every member account.
  EOT
  type        = string
  default     = ""
}

variable "backup_regions" {
  description = <<-EOT
    Regions where the centralized backup plan runs (this does NOT copy backups
    between regions; use copy_destination_region for that). Defaults assume a
    standard AWS commercial deployment (us-east-1, us-west-2) — if
    deploying in AWS GovCloud, override with GovCloud region names
    (e.g. us-gov-west-1, us-gov-east-1) instead, since the two partitions
    don't share regions.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}
