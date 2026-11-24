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
  # Attaching with no exemptions fails the module's check block, which
  # terraform test treats as a run failure.
  exempt_principal_arns = ["arn:aws:iam::*:role/terraform-deployer"]
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
    approved_regions = ["us-east-2", "us-west-1"]
  }

  assert {
    condition = toset(
      one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).Condition.StringNotEquals["aws:RequestedRegion"]
    ) == toset(["us-east-2", "us-west-1"])
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

run "imdsv2_is_off_by_default" {
  command = plan

  assert {
    condition     = length([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if startswith(s.Sid, "Deny") && strcontains(s.Sid, "IMDS")]) == 0
    error_message = "IMDSv2 enforcement must stay opt-in, so existing launch templates keep working."
  }
}

run "imdsv2_denies_launch_and_downgrade" {
  command = plan

  variables {
    require_imdsv2 = true
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyLaunchWithoutIMDSv2"]).Condition.StringNotEquals["ec2:MetadataHttpTokens"] == "required"
    error_message = "With require_imdsv2, launching an instance without HttpTokens = required must be denied."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyDowngradeToIMDSv1"]).Action == "ec2:ModifyInstanceMetadataOptions"
    error_message = "With require_imdsv2, switching an instance back to IMDSv1 must be denied."
  }

  # SCPs are capped at 5,120 characters and whitespace counts, so measure
  # the content the module actually submits (minified).
  assert {
    condition     = length(aws_organizations_policy.fedramp_boundary.content) <= 5120
    error_message = "With every statement enabled, the SCP must stay within the 5,120-character limit."
  }
}

run "mfa_removal_requires_mfa" {
  command = plan

  variables {
    exempt_principal_arns = ["arn:aws:iam::*:role/mfa-admin"]
  }

  assert {
    condition     = toset(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyMfaRemovalWithoutMfa"]).Action) == toset(["iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice"])
    error_message = "The MFA statement must deny exactly deactivate and delete: never enrolment (first enrolment has no MFA) or resync (a drifted device must stay recoverable)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyMfaRemovalWithoutMfa"]).Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "false"
    error_message = "MFA removal must be denied when MFA is absent or false."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyMfaRemovalWithoutMfa"]).Condition.ArnNotLike["aws:PrincipalArn"] == "arn:aws:iam::*:role/mfa-admin"
    error_message = "Exempt principals must be excluded from the MFA removal deny."
  }
}

run "no_exemptions_means_unconditional_denies" {
  command = plan

  variables {
    target_ou_or_account_ids = [] # unattached, so the check block stays quiet
    exempt_principal_arns    = []
  }

  assert {
    condition = alltrue([
      for sid in ["DenyDisablingSecurityServices", "DenyModifyingAccountBaseline"] :
      !can(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == sid]).Condition)
    ])
    error_message = "With no exempt_principal_arns, the security-service and baseline denies must apply to everyone."
  }
}

run "exempt_principals_skip_the_baseline_denies" {
  command = plan

  variables {
    exempt_principal_arns = ["arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAdmin_*", "arn:aws:iam::*:role/terraform-deployer"]
    require_imdsv2        = true # largest policy, for the size check
  }

  assert {
    condition = alltrue([
      for sid in ["DenyDisablingSecurityServices", "DenyModifyingAccountBaseline", "DenyMfaRemovalWithoutMfa"] :
      toset(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == sid]).Condition.ArnNotLike["aws:PrincipalArn"]) == toset(["arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAdmin_*", "arn:aws:iam::*:role/terraform-deployer"])
    ])
    error_message = "Every exempt principal must be excluded from the security-service and baseline denies."
  }

  assert {
    condition     = !can(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).Condition.ArnNotLike)
    error_message = "Exempt principals must still be held to the approved regions."
  }

  # Organizations rejects an SCP over 5,120 characters.
  assert {
    condition     = length(aws_organizations_policy.fedramp_boundary.content) <= 5120
    error_message = "The SCP is over the 5,120-character Organizations limit."
  }
}

run "govcloud_six_long_exemptions_fit_the_size_limit" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws-us-gov"
    }
  }

  variables {
    require_imdsv2 = true
    exempt_principal_arns = [
      for name in ["SecurityAdmin", "NetworkAdmin", "PlatformAdmin", "BreakGlassAdmin", "IdentityAdmin", "AuditorReadOnly"] :
      "arn:aws-us-gov:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_${name}_*"
    ]
  }

  assert {
    condition     = length(aws_organizations_policy.fedramp_boundary.content) <= 5120
    error_message = "Six SSO-style exempt ARNs with require_imdsv2 in GovCloud must fit the 5,120-character limit."
  }

  assert {
    condition     = !strcontains(aws_organizations_policy.fedramp_boundary.content, "\n")
    error_message = "The submitted SCP must be minified."
  }
}

run "rejects_an_oversized_policy" {
  command = plan

  variables {
    exempt_principal_arns = [for i in range(30) : "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Role${i}_*"]
  }

  expect_failures = [aws_organizations_policy.fedramp_boundary]
}

run "global_services_are_exempt_from_the_region_lock" {
  command = plan

  assert {
    condition = alltrue([
      for action in ["sts:*", "ce:*", "health:*", "s3:ListAllMyBuckets"] :
      contains(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).NotAction, action)
    ])
    error_message = "Global services must stay exempt from the region lock, or they break when approved_regions leaves out us-east-1."
  }

  assert {
    condition     = !contains(one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).NotAction, "wafv2:*")
    error_message = "WAFv2 has regional resources; exempting it would let web ACLs be created outside approved_regions."
  }
}

run "commercial_partition_defaults_to_commercial_regions" {
  command = plan

  assert {
    condition = toset(
      one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).Condition.StringNotEquals["aws:RequestedRegion"]
    ) == toset(["us-east-1", "us-west-2"])
    error_message = "With approved_regions unset in the aws partition, the lock must allow us-east-1 and us-west-2."
  }
}

run "govcloud_partition_defaults_to_govcloud_regions" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws-us-gov"
    }
  }

  assert {
    condition = toset(
      one([for s in jsondecode(data.aws_iam_policy_document.fedramp_boundary_scp.json).Statement : s if s.Sid == "DenyUnapprovedRegions"]).Condition.StringNotEquals["aws:RequestedRegion"]
    ) == toset(["us-gov-west-1", "us-gov-east-1"])
    error_message = "With approved_regions unset in GovCloud, the lock must allow only us-gov-west-1 and us-gov-east-1."
  }
}

run "govcloud_rejects_commercial_regions" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws-us-gov"
    }
  }

  variables {
    approved_regions = ["us-gov-west-1", "us-east-1"]
  }

  expect_failures = [aws_organizations_policy.fedramp_boundary]
}

run "commercial_rejects_govcloud_regions" {
  command = plan

  variables {
    approved_regions = ["us-gov-west-1", "us-gov-east-1"]
  }

  expect_failures = [aws_organizations_policy.fedramp_boundary]
}

run "rejects_empty_approved_regions" {
  command = plan

  variables {
    approved_regions = []
  }

  expect_failures = [aws_organizations_policy.fedramp_boundary]
}

run "warns_when_attached_without_exemptions" {
  command = plan

  variables {
    exempt_principal_arns = []
  }

  expect_failures = [check.exempt_principals_set_when_attached]
}

run "no_warning_when_not_attached" {
  command = plan

  variables {
    target_ou_or_account_ids = []
    exempt_principal_arns    = []
  }
}
