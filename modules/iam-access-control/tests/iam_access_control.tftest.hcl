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
