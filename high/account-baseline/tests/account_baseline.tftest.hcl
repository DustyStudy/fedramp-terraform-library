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

# The EBS key is created in the same plan, so its ARN is unknown here. The
# plan itself is the check: it failed with "Invalid count argument" when the
# module decided from the ARN.
run "plans_with_a_key_created_in_the_same_plan" {
  command = plan
}
