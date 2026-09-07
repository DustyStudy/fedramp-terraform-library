variable "organization_id" {
  type        = string
  description = "AWS Organizations ID (e.g. o-xxxxxxxxxx)."

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must match the AWS Organizations ID format, e.g. o-xxxxxxxxxx."
  }
}

variable "approved_regions" {
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
  description = "Regions permitted org-wide by the SCP region lock. Use GovCloud region names if deploying in AWS GovCloud."
}

variable "target_ou_or_account_ids" {
  type        = list(string)
  description = "Organizational Unit or account IDs the SCPs attach to (e.g. [\"ou-xxxx-xxxxxxxx\"])."
}

variable "authorized_security_admin_arns" {
  type        = list(string)
  default     = []
  description = "IAM role/user ARNs exempted from the S3 Object Lock protection statement in org-governance's SCP (e.g. your break-glass or security-admin role). Leave empty and legitimate retention management gets denied too — see modules/org-governance/README.md."
}
