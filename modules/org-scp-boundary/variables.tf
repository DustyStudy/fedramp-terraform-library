variable "policy_name" {
  description = "Name of the SCP"
  type        = string
  default     = "fedramp-authorization-boundary-scp"
}

variable "approved_regions" {
  description = <<-EOT
    Regions the SCP allows. null (the default) picks them from the
    partition the provider runs in: us-gov-west-1 and us-gov-east-1 in
    GovCloud, us-east-1 and us-west-2 elsewhere. A list must be non-empty
    and belong to that partition (only us-gov-* regions in GovCloud, none
    of them outside it), or the plan fails: a region lock naming another
    partition's regions denies every regional action in the targets.
  EOT
  type        = list(string)
  default     = null
}

variable "target_ou_or_account_ids" {
  description = "List of Organizational Units or Account IDs to attach this SCP"
  type        = list(string)
  default     = []
}

variable "require_imdsv2" {
  description = <<-EOT
    Add statements that deny launching an EC2 instance without IMDSv2
    (HttpTokens = required) and deny switching an instance back to IMDSv1.
    Off by default: turning it on breaks any launch template, AMI pipeline
    or tool that still sets HttpTokens to optional.
  EOT
  type        = bool
  default     = false
}

variable "exempt_principal_arns" {
  description = <<-EOT
    IAM role ARNs (wildcards allowed, e.g. an Identity Center permission set
    role "arn:<partition>:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAdmin_*")
    that the security-service and account-baseline denies do not apply to.
    Without one, nobody in a member account, including your deployment
    pipeline, can create the S3 account public access block, enable
    GuardDuty features or delete a KMS key once the SCP is attached.
  EOT
  type        = list(string)
  default     = []
}
