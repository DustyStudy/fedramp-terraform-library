# Plan-only test. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-gov-west-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = module.account_baseline.data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = module.account_baseline.data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

override_data {
  target = module.account_baseline.data.aws_iam_roles.autoscaling
  values = {
    arns = []
  }
}

run "sets_a_customer_managed_default_ebs_key" {
  command = plan

  assert {
    condition     = output.ebs_encryption_enabled
    error_message = "EBS encryption by default must be on (SC-28)."
  }
}
