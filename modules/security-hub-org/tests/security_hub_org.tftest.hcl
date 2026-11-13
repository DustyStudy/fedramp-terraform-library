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

run "subscribes_to_nist_800_53_in_the_current_partition" {
  command = plan

  assert {
    condition     = aws_securityhub_standards_subscription.nist_800_53[0].standards_arn == "arn:${data.aws_partition.current.partition}:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"
    error_message = "FedRAMP builds on NIST SP 800-53 Rev5; the standard must be subscribed."
  }

  assert {
    condition     = length(aws_securityhub_finding_aggregator.this) == 0
    error_message = "The finding aggregator must be opt-in: only one region may hold it."
  }
}

run "aggregator_links_all_regions" {
  command = plan

  variables {
    enable_finding_aggregator = true
  }

  assert {
    condition     = aws_securityhub_finding_aggregator.this[0].linking_mode == "ALL_REGIONS"
    error_message = "The aggregator must collect findings from every region."
  }
}
