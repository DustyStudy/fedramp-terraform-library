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
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

variables {
  use_fips_endpoint = false
  key_alias         = "app-data"
}

run "key_rotates_with_a_bounded_deletion_window" {
  command = plan

  assert {
    condition     = aws_kms_key.this.enable_key_rotation && aws_kms_key.this.deletion_window_in_days >= 7 && aws_kms_key.this.deletion_window_in_days <= 30
    error_message = "The CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }
}

run "root_only_policy_without_key_users" {
  command = plan

  assert {
    condition     = [for s in jsondecode(data.aws_iam_policy_document.cmk.json).Statement : s.Sid] == ["AllowRootAccountAdmin"]
    error_message = "With no admin or user roles the key policy must hold only the account-root statement."
  }
}

run "key_users_can_grant_to_aws_services_only" {
  command = plan

  variables {
    key_user_role_arns = ["arn:aws-us-gov:iam::123456789012:role/app"]
  }

  assert {
    condition     = toset(one([for s in jsondecode(data.aws_iam_policy_document.cmk.json).Statement : s if s.Sid == "AllowAttachmentOfPersistentResources"]).Action) == toset(["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"])
    error_message = "Key users need the grant actions to launch encrypted EBS volumes and RDS instances."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.cmk.json).Statement : s if s.Sid == "AllowAttachmentOfPersistentResources"]).Condition.Bool["kms:GrantIsForAWSResource"] == "true"
    error_message = "Grants by key users must be limited to AWS services (kms:GrantIsForAWSResource)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.cmk.json).Statement : s if s.Sid == "AllowAttachmentOfPersistentResources"]).Principal.AWS == "arn:aws-us-gov:iam::123456789012:role/app"
    error_message = "The grant statement must name the key user roles."
  }

  assert {
    condition     = !contains(flatten([one([for s in jsondecode(data.aws_iam_policy_document.cmk.json).Statement : s if s.Sid == "AllowKeyUsage"]).Action]), "kms:CreateGrant")
    error_message = "kms:CreateGrant must not be granted without the kms:GrantIsForAWSResource condition."
  }
}
