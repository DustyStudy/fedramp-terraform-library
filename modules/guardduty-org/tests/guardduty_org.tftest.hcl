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
    partition = "aws"
  }
}

run "detector_enables_all_classic_protections" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this.enable
    error_message = "The GuardDuty detector must be enabled (SI-4)."
  }

  assert {
    condition     = alltrue([for f in aws_guardduty_detector_feature.this : f.status == "ENABLED"])
    error_message = "Every protection must be on."
  }

  assert {
    condition     = toset(keys(aws_guardduty_detector_feature.this)) == toset(["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION"])
    error_message = "S3, EKS audit log and EBS malware protection must all be managed."
  }
}

run "new_accounts_are_enrolled" {
  command = plan

  assert {
    condition     = aws_guardduty_organization_configuration.this.auto_enable_organization_members == "NEW"
    error_message = "Accounts joining the organization must be enrolled automatically by default."
  }

  assert {
    condition     = alltrue([for f in aws_guardduty_organization_configuration_feature.this : f.auto_enable == "NEW"])
    error_message = "Each protection must be turned on for accounts that join the organization."
  }
}

run "findings_alert_at_medium_or_higher" {
  command = plan

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty_findings.event_pattern).detail.severity[0].numeric == [">=", 4]
    error_message = "The EventBridge rule must route findings of severity 4 (Medium) and above."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(data.aws_iam_policy_document.guardduty_findings_kms.json).Statement :
      try(s.Principal.Service, "") == "events.amazonaws.com" if s.Effect == "Allow"
    ])
    error_message = "The topic CMK must trust EventBridge, or findings are silently dropped."
  }
}

run "auto_enable_false_requires_none" {
  command = plan

  variables {
    auto_enable = false
  }

  expect_failures = [aws_guardduty_organization_configuration.this]
}

run "rejects_unknown_publishing_frequency" {
  command = plan

  variables {
    finding_publishing_frequency = "FIVE_MINUTES"
  }

  expect_failures = [var.finding_publishing_frequency]
}
