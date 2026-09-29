# Plan-only tests. Dummy credentials keep the real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

run "defaults_follow_nist_800_63b_4" {
  command = plan

  assert {
    condition     = aws_iam_account_password_policy.this.minimum_password_length == 15
    error_message = "Default minimum length must be 15 for single-factor passwords."
  }

  assert {
    condition = !anytrue([
      aws_iam_account_password_policy.this.require_uppercase_characters,
      aws_iam_account_password_policy.this.require_lowercase_characters,
      aws_iam_account_password_policy.this.require_numbers,
      aws_iam_account_password_policy.this.require_symbols,
    ])
    error_message = "Composition rules must be off by default (800-63B-4 says SHALL NOT)."
  }

  assert {
    condition     = aws_iam_account_password_policy.this.max_password_age == 0
    error_message = "Periodic expiry must be off by default."
  }

  assert {
    condition     = aws_iam_account_password_policy.this.password_reuse_prevention == 24
    error_message = "The last 24 passwords must be remembered by default."
  }
}

run "composition_rules_are_opt_in" {
  command = plan

  variables {
    require_symbols = true
  }

  assert {
    condition     = aws_iam_account_password_policy.this.require_symbols
    error_message = "Setting require_symbols must turn the rule on."
  }
}

run "rejects_length_below_nist_floor" {
  command = plan

  variables {
    minimum_password_length = 6
  }

  expect_failures = [var.minimum_password_length]
}
