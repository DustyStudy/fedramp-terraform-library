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
  default     = null
  description = "Regions permitted org-wide by the SCP region lock. null picks them from the partition: us-gov-west-1 and us-gov-east-1 in GovCloud, us-east-1 and us-west-2 elsewhere."
}

variable "exempt_principal_arns" {
  type        = list(string)
  description = <<-EOT
    IAM role ARNs (wildcards allowed) the SCP's security-service and
    account-baseline denies do not apply to. No default on purpose: include
    the role that applies member-account-baseline/ in each member account
    (e.g. "arn:<partition>:iam::*:role/terraform-deployer") and the role
    this root assumes in the security account, or those applies fail with
    AccessDenied on s3:PutAccountPublicAccessBlock and guardduty:UpdateDetector.
    Pass [] only if you accept that.
  EOT
}

variable "security_account_id" {
  type        = string
  description = "Account ID of the security account, designated here as the GuardDuty and Security Hub delegated administrator. Must not be the management account."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_account_id))
    error_message = "security_account_id must be a 12-digit AWS account ID."
  }
}

variable "security_account_role_name" {
  type        = string
  default     = "OrganizationAccountAccessRole"
  description = "Role in the security account that the management-account credentials assume to configure GuardDuty and Security Hub there."
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
