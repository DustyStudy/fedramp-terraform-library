# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

variables {
  target_ou_or_account_ids       = ["ou-abcd-11111111", "123456789012"]
  authorized_security_admin_arns = ["arn:aws-us-gov:iam::123456789012:role/SecurityAdmin"]
  backup_regions                 = ["us-gov-west-1", "us-gov-east-1"]
}

run "perimeter_scp_denies" {
  command = plan

  assert {
    condition     = alltrue([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s.Effect == "Deny"])
    error_message = "Every perimeter SCP statement must be a Deny."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyRootUserActions"]).Condition.StringLike["aws:PrincipalArn"] == "arn:aws-us-gov:iam::*:root"
    error_message = "The root deny must match root in the current partition (AC-6(2))."
  }

  assert {
    condition = toset(one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyDirectInternetGateways"]).Action) == toset([
      "ec2:CreateInternetGateway", "ec2:AttachInternetGateway", "ec2:CreateEgressOnlyInternetGateway",
    ])
    error_message = "The SCP must deny creating and attaching internet gateways (SC-7)."
  }

  assert {
    condition     = toset(one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyLocalIAMUsersAndAccessKeys"]).Action) == toset(["iam:CreateUser", "iam:CreateAccessKey"])
    error_message = "The SCP must deny IAM users and access keys (IA-2, IA-5)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyRootUserActions"]).Action == "*" && alltrue([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s.Resource == "*"])
    error_message = "The root deny must cover every action, and every statement every resource."
  }

  assert {
    condition     = toset(one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyBypassOrDeleteObjectLock"]).Action) == toset(["s3:BypassGovernanceRetention", "s3:PutObjectLegalHold", "s3:PutObjectRetention"])
    error_message = "The SCP must deny bypassing governance retention and changing holds and retention (AU-9)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyBypassOrDeleteObjectLock"]).Condition.StringNotEquals["aws:PrincipalArn"] == "arn:aws-us-gov:iam::123456789012:role/SecurityAdmin"
    error_message = "Only the authorized security admins may change Object Lock settings (AU-9)."
  }
}

run "policy_types_and_attachments" {
  command = plan

  assert {
    condition     = aws_organizations_policy.workload_perimeter.type == "SERVICE_CONTROL_POLICY" && aws_organizations_policy.ai_opt_out.type == "AISERVICES_OPT_OUT_POLICY" && aws_organizations_policy.backup_policy.type == "BACKUP_POLICY"
    error_message = "Each policy must have the right Organizations policy type."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.perimeter_attachment) == 2 && length(aws_organizations_policy_attachment.ai_opt_out_attachment) == 2 && length(aws_organizations_policy_attachment.backup_attachment) == 2
    error_message = "Each policy must attach once per OU or account in target_ou_or_account_ids."
  }

  assert {
    condition = alltrue([
      for a in [aws_organizations_policy_attachment.perimeter_attachment, aws_organizations_policy_attachment.ai_opt_out_attachment, aws_organizations_policy_attachment.backup_attachment] :
      [for x in a : x.target_id] == ["ou-abcd-11111111", "123456789012"]
    ])
    error_message = "Each policy must attach to exactly the given targets."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.ai_opt_out.content).services.default.opt_out_policy["@@assign"] == "optOut" && jsondecode(aws_organizations_policy.ai_opt_out.content).services.default.opt_out_policy["@@operators_allowed_for_child_policies"] == ["@@none"]
    error_message = "AI services must be opted out, and child policies must not be able to opt back in."
  }
}

run "backup_policy_without_copy" {
  command = plan

  assert {
    condition     = jsondecode(aws_organizations_policy.backup_policy.content).plans.FedRAMPDailyBackupPlan.regions["@@assign"] == ["us-gov-west-1", "us-gov-east-1"]
    error_message = "The backup plan must run in backup_regions."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.backup_policy.content).plans.FedRAMPDailyBackupPlan.rules.DailyRule.lifecycle.delete_after_days["@@assign"] == 365
    error_message = "Backups must be kept backup_retention_days (default 365) (CP-9)."
  }

  assert {
    condition     = !can(jsondecode(aws_organizations_policy.backup_policy.content).plans.FedRAMPDailyBackupPlan.rules.DailyRule.copy_actions)
    error_message = "No copy action may be added when copy_destination_region is empty."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.backup_policy.content).plans.FedRAMPDailyBackupPlan.selections.tags.FedRAMPBackup.iam_role_arn["@@assign"] == "arn:aws-us-gov:iam::$account:role/service-role/AWSBackupDefaultServiceRole"
    error_message = "The backup role ARN must be built from the current partition."
  }
}

run "backup_policy_with_copy" {
  command = plan

  variables {
    copy_destination_region = "us-gov-east-1"
  }

  assert {
    condition = keys(jsondecode(aws_organizations_policy.backup_policy.content).plans.FedRAMPDailyBackupPlan.rules.DailyRule.copy_actions) == [
      "arn:aws-us-gov:backup:us-gov-east-1:$account:backup-vault:FedRAMPComplianceVault",
    ]
    error_message = "A cross-region copy must target the same vault name in copy_destination_region (CP-9, CP-6)."
  }
}

run "rejects_short_retention" {
  command = plan

  variables {
    backup_retention_days = 90
  }

  expect_failures = [var.backup_retention_days]
}


run "no_admins_means_unconditional_object_lock_deny" {
  command = plan

  variables {
    authorized_security_admin_arns = []
  }

  assert {
    condition     = !can(one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyBypassOrDeleteObjectLock"]).Condition)
    error_message = "With no authorized admins, the Object Lock deny must have no condition, not an empty one (AU-9)."
  }
}

run "several_admins_are_all_exempt" {
  command = plan

  variables {
    authorized_security_admin_arns = [
      "arn:aws-us-gov:iam::123456789012:role/SecurityAdmin",
      "arn:aws-us-gov:iam::123456789012:role/BreakGlass",
    ]
  }

  assert {
    condition = toset(one([for s in jsondecode(data.aws_iam_policy_document.workload_perimeter_scp.json).Statement : s if s.Sid == "DenyBypassOrDeleteObjectLock"]).Condition.StringNotEquals["aws:PrincipalArn"]) == toset([
      "arn:aws-us-gov:iam::123456789012:role/SecurityAdmin",
      "arn:aws-us-gov:iam::123456789012:role/BreakGlass",
    ])
    error_message = "Every authorized admin must be exempt from the Object Lock deny."
  }
}
