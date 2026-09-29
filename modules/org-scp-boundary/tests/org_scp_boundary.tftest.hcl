# Plan-only tests. The real AWS provider renders the policy JSON locally;
# dummy credentials with validation skipped keep it from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

variables {
  target_ou_or_account_ids = ["ou-abcd-11111111", "123456789012"]
}

run "denies_disabling_security_services" {
  command = plan

  assert {
    condition = alltrue([
      for action in [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "securityhub:DisableSecurityHub",
        "kms:ScheduleKeyDeletion",
      ] : contains(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyDisablingSecurityServices"]).Action, action)
    ])
    error_message = "The SCP must deny stopping or deleting CloudTrail, Config, GuardDuty, Security Hub, and KMS keys."
  }

  assert {
    condition     = alltrue([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s.Effect == "Deny"])
    error_message = "Every SCP statement must be a Deny."
  }
}

run "region_lock_uses_approved_regions" {
  command = plan

  variables {
    approved_regions = ["us-gov-west-1", "us-gov-east-1"]
  }

  assert {
    condition = toset(
      one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).Condition.StringNotEquals["aws:RequestedRegion"]
    ) == toset(["us-gov-west-1", "us-gov-east-1"])
    error_message = "The region lock must deny every region outside approved_regions."
  }

  assert {
    condition     = contains(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).NotAction, "iam:*")
    error_message = "Global services such as IAM must stay exempt from the region lock."
  }
}

run "denies_insecure_transport" {
  command = plan

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyInsecureTransport"]).Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "The SCP must deny requests made without TLS (SC-8)."
  }
}

run "attaches_to_every_target" {
  command = plan

  assert {
    condition     = length(aws_organizations_policy_attachment.target_attachment) == 2
    error_message = "The SCP must attach once per OU or account in target_ou_or_account_ids."
  }

  assert {
    condition     = aws_organizations_policy.fedramp_boundary.type == "SERVICE_CONTROL_POLICY"
    error_message = "The policy must be a service control policy."
  }
}
