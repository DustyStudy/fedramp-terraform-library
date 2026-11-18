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

run "unused_access_analyzer_uses_the_unused_access_type" {
  command = plan

  assert {
    condition     = aws_accessanalyzer_analyzer.unused_access.type == "ACCOUNT_UNUSED_ACCESS"
    error_message = "An unused-access analyzer must be created with the *_UNUSED_ACCESS type."
  }
}

# IAM refused the policy in the live proof: "Resource vendor must be fully
# qualified and cannot contain regexes."
run "boundary_resources_name_their_service" {
  command = plan

  assert {
    condition = alltrue([
      for resource in flatten([
        for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement : s.Resource
      ]) : resource == "*" || !strcontains(split(":", resource)[2], "*")
    ])
    error_message = "No ARN in the boundary may have a wildcard in its service field."
  }
}

run "boundary_scopes_s3_to_this_account" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
      try(s.Condition.StringEquals["s3:ResourceAccount"], "") == "123456789012"
    ])
    error_message = "S3 access under the boundary must be limited to buckets this account owns."
  }
}

# AWS reference policy "Allows MFA-authenticated IAM users to manage their own
# credentials", statement DenyAllExceptListedIfNoMFA.
run "mfa_deny_exempts_what_the_aws_reference_exempts" {
  command = plan

  assert {
    condition = toset(jsondecode(data.aws_iam_policy_document.require_mfa.json).Statement[0].NotAction) == toset([
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:GetMFADevice",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken",
    ])
    error_message = "By default the MFA deny must exempt exactly the actions AWS's reference policy exempts (no password change without MFA)."
  }
}

run "mfa_deny_can_exempt_first_sign_in_password_change" {
  command = plan

  variables {
    allow_password_change_without_mfa = true
  }

  assert {
    condition = length(setsubtract(
      ["iam:ChangePassword", "iam:GetAccountPasswordPolicy"],
      jsondecode(data.aws_iam_policy_document.require_mfa.json).Statement[0].NotAction
    )) == 0
    error_message = "allow_password_change_without_mfa must exempt both password actions from the MFA deny."
  }
}

run "boundary_passes_only_developer_path_roles_to_lambda" {
  command = plan

  variables {
    developer_role_path = "/team-a/"
  }

  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
      [s.Resource, s.Condition.StringEquals["iam:PassedToService"]]
      if s.Effect == "Allow" && contains(flatten([s.Action]), "iam:PassRole")
    ] == [["arn:aws-us-gov:iam::123456789012:role/team-a/*", "lambda.amazonaws.com"]]
    error_message = "iam:PassRole must be allowed once, on the developer role path only, and only to Lambda."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
      alltrue([for a in flatten([s.Action]) : !startswith(a, "iam:") || a == "iam:PassRole"])
      if s.Effect == "Allow"
    ])
    error_message = "PassRole is the only iam: action the boundary may allow."
  }
}

run "boundary_rejects_a_role_path_that_covers_every_role" {
  command = plan

  variables {
    developer_role_path = "/"
  }

  expect_failures = [var.developer_role_path]
}

run "boundary_allows_kms_use_only_through_its_services" {
  command = plan

  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
      toset(s.Condition.StringLike["kms:ViaService"])
      if s.Effect == "Allow" && contains(flatten([s.Action]), "kms:Decrypt")
      ] == [toset([
        "dynamodb.*.amazonaws.com", "lambda.*.amazonaws.com", "s3.*.amazonaws.com",
        "sns.*.amazonaws.com", "sqs.*.amazonaws.com",
    ])]
    error_message = "kms:Decrypt must be allowed only via the services the boundary allows."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
      alltrue([for a in flatten([s.Action]) : !startswith(a, "logs:") || !strcontains(a, "*")])
      if s.Effect == "Allow"
    ])
    error_message = "CloudWatch Logs actions under the boundary must be listed, not wildcarded."
  }
}

run "boundary_denies_resource_policy_and_public_access_changes" {
  command = plan

  assert {
    condition = length(setsubtract(
      [
        "dynamodb:PutResourcePolicy",
        "lambda:AddPermission",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock",
        "sns:AddPermission",
        "sns:SetTopicAttributes",
        "sqs:AddPermission",
        "sqs:SetQueueAttributes",
      ],
      flatten([
        for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
        s.Action if s.Effect == "Deny" && s.Resource == "*" && !can(s.Condition)
      ])
    )) == 0
    error_message = "The boundary must unconditionally deny the actions that expose a resource to other accounts or the public."
  }
}

run "boundary_denies_removing_itself" {
  command = plan

  assert {
    condition = length(setsubtract(
      ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"],
      flatten([
        for s in jsondecode(data.aws_iam_policy_document.developer_permission_boundary.json).Statement :
        s.Action if s.Effect == "Deny" && s.Resource == "*" && !can(s.Condition)
      ])
    )) == 0
    error_message = "Removing a permissions boundary must be denied without a condition."
  }
}
