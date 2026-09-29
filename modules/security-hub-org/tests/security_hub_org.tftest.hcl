# Plan-only tests. Dummy credentials keep the real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

run "enables_default_standards_and_org_enrollment" {
  command = plan

  assert {
    condition     = aws_securityhub_account.this.enable_default_standards
    error_message = "Security Hub must enable its default standards (CA-7, RA-5)."
  }

  assert {
    condition     = aws_securityhub_organization_configuration.this.auto_enable && aws_securityhub_organization_configuration.this.auto_enable_standards == "DEFAULT"
    error_message = "New member accounts must be enrolled with the default standards."
  }
}

run "standards_auto_enable_can_be_turned_off" {
  command = plan

  variables {
    auto_enable_standards = false
  }

  assert {
    condition     = aws_securityhub_organization_configuration.this.auto_enable_standards == "NONE"
    error_message = "auto_enable_standards = false must map to NONE."
  }
}
