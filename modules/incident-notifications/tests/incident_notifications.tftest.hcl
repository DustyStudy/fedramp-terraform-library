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

override_resource {
  target          = aws_kms_key.incident_notifications
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/incident"
  }
}

override_resource {
  target          = aws_sns_topic.incident_notifications
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:sns:us-gov-west-1:123456789012:security-incident-notifications"
  }
}

run "topic_is_encrypted_and_scoped" {
  command = plan

  # The topic policy's aws:SourceArn scoping is not checked here: the policy
  # document stays unknown at plan time even with the rule ARNs overridden.

  assert {
    condition     = aws_kms_key.incident_notifications.enable_key_rotation && aws_kms_key.incident_notifications.deletion_window_in_days >= 7 && aws_kms_key.incident_notifications.deletion_window_in_days <= 30
    error_message = "The topic CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.incident_notifications_kms.json).Statement : s if s.Sid == "AllowEventBridgePublish"]).Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "EventBridge use of the key must be limited to this account (confused deputy)."
  }
}

run "routes_high_severity_findings" {
  command = plan

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty_high_severity.event_pattern).source == ["aws.guardduty"] && jsondecode(aws_cloudwatch_event_rule.guardduty_high_severity.event_pattern)["detail-type"] == ["GuardDuty Finding"]
    error_message = "The GuardDuty rule must match GuardDuty finding events."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.securityhub_critical_high.event_pattern).source == ["aws.securityhub"] && jsondecode(aws_cloudwatch_event_rule.securityhub_critical_high.event_pattern)["detail-type"] == ["Security Hub Findings - Imported"]
    error_message = "The Security Hub rule must match imported finding events."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty_high_severity.event_pattern).detail.severity[0].numeric == [">=", 7]
    error_message = "GuardDuty findings of severity 7 and up must be routed by default (IR-6)."
  }

  assert {
    condition     = toset(jsondecode(aws_cloudwatch_event_rule.securityhub_critical_high.event_pattern).detail.findings.Severity.Label) == toset(["CRITICAL", "HIGH"])
    error_message = "Security Hub CRITICAL and HIGH findings must be routed (IR-6)."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.securityhub_critical_high.event_pattern).detail.findings.Workflow.Status == ["NEW"]
    error_message = "Only new Security Hub findings should page, so updates to the same finding do not repeat."
  }
}

run "findings_reach_the_encrypted_topic" {
  command = plan

  assert {
    condition     = aws_sns_topic.incident_notifications.kms_master_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/incident"
    error_message = "The topic must be encrypted with the module's CMK (SC-28)."
  }

  assert {
    condition = alltrue([
      for t in [aws_cloudwatch_event_target.guardduty_high_severity, aws_cloudwatch_event_target.securityhub_critical_high] :
      t.arn == "arn:aws-us-gov:sns:us-gov-west-1:123456789012:security-incident-notifications"
    ])
    error_message = "Both rules must deliver to the incident topic (IR-6)."
  }
}

run "rejects_out_of_range_threshold" {
  command = plan

  variables {
    guardduty_severity_threshold = 11
  }

  expect_failures = [var.guardduty_severity_threshold]
}

