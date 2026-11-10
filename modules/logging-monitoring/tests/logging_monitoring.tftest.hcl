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
  target          = aws_kms_key.cis_alarms
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/cis"
  }
}

override_resource {
  target          = aws_sns_topic.cis_alarms
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:sns:us-gov-west-1:123456789012:cis-benchmark-alarms"
  }
}

variables {
  cloudtrail_log_group_name = "aws-cloudtrail-logs"
}

run "every_alarm_watches_its_filter_metric" {
  command = plan

  assert {
    condition = alltrue([
      for p in [
        [aws_cloudwatch_log_metric_filter.root_usage, aws_cloudwatch_metric_alarm.root_usage],
        [aws_cloudwatch_log_metric_filter.unauthorized_api_calls, aws_cloudwatch_metric_alarm.unauthorized_api_calls],
        [aws_cloudwatch_log_metric_filter.console_signin_without_mfa, aws_cloudwatch_metric_alarm.console_signin_without_mfa],
        [aws_cloudwatch_log_metric_filter.iam_policy_changes, aws_cloudwatch_metric_alarm.iam_policy_changes],
        [aws_cloudwatch_log_metric_filter.cloudtrail_config_changes, aws_cloudwatch_metric_alarm.cloudtrail_config_changes],
        [aws_cloudwatch_log_metric_filter.console_auth_failures, aws_cloudwatch_metric_alarm.console_auth_failures],
        [aws_cloudwatch_log_metric_filter.cmk_disable_or_delete, aws_cloudwatch_metric_alarm.cmk_disable_or_delete],
        [aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes, aws_cloudwatch_metric_alarm.s3_bucket_policy_changes],
        [aws_cloudwatch_log_metric_filter.config_config_changes, aws_cloudwatch_metric_alarm.config_config_changes],
        [aws_cloudwatch_log_metric_filter.security_group_changes, aws_cloudwatch_metric_alarm.security_group_changes],
        [aws_cloudwatch_log_metric_filter.nacl_changes, aws_cloudwatch_metric_alarm.nacl_changes],
        [aws_cloudwatch_log_metric_filter.network_gateway_changes, aws_cloudwatch_metric_alarm.network_gateway_changes],
        [aws_cloudwatch_log_metric_filter.route_table_changes, aws_cloudwatch_metric_alarm.route_table_changes],
        [aws_cloudwatch_log_metric_filter.vpc_changes, aws_cloudwatch_metric_alarm.vpc_changes],
      ] : p[0].metric_transformation[0].name == p[1].metric_name && p[0].metric_transformation[0].namespace == p[1].namespace
    ])
    error_message = "Each CIS alarm must watch the metric its own filter publishes, or it can never fire (SI-4)."
  }

  assert {
    condition = alltrue([
      for f in [
        aws_cloudwatch_log_metric_filter.root_usage,
        aws_cloudwatch_log_metric_filter.unauthorized_api_calls,
        aws_cloudwatch_log_metric_filter.console_signin_without_mfa,
        aws_cloudwatch_log_metric_filter.iam_policy_changes,
        aws_cloudwatch_log_metric_filter.cloudtrail_config_changes,
        aws_cloudwatch_log_metric_filter.console_auth_failures,
        aws_cloudwatch_log_metric_filter.cmk_disable_or_delete,
        aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes,
        aws_cloudwatch_log_metric_filter.config_config_changes,
        aws_cloudwatch_log_metric_filter.security_group_changes,
        aws_cloudwatch_log_metric_filter.nacl_changes,
        aws_cloudwatch_log_metric_filter.network_gateway_changes,
        aws_cloudwatch_log_metric_filter.route_table_changes,
        aws_cloudwatch_log_metric_filter.vpc_changes,
      ] : f.log_group_name == "aws-cloudtrail-logs" && f.metric_transformation[0].value == "1"
    ])
    error_message = "Every metric filter must read the CloudTrail log group and count one per matching event."
  }
}

run "alarms_fire_on_first_event" {
  command = plan

  assert {
    condition = alltrue([
      for a in [
        aws_cloudwatch_metric_alarm.root_usage,
        aws_cloudwatch_metric_alarm.unauthorized_api_calls,
        aws_cloudwatch_metric_alarm.console_signin_without_mfa,
        aws_cloudwatch_metric_alarm.iam_policy_changes,
        aws_cloudwatch_metric_alarm.cloudtrail_config_changes,
        aws_cloudwatch_metric_alarm.console_auth_failures,
        aws_cloudwatch_metric_alarm.cmk_disable_or_delete,
        aws_cloudwatch_metric_alarm.s3_bucket_policy_changes,
        aws_cloudwatch_metric_alarm.config_config_changes,
        aws_cloudwatch_metric_alarm.security_group_changes,
        aws_cloudwatch_metric_alarm.nacl_changes,
        aws_cloudwatch_metric_alarm.network_gateway_changes,
        aws_cloudwatch_metric_alarm.route_table_changes,
        aws_cloudwatch_metric_alarm.vpc_changes,
      ] : a.threshold == 1 && a.evaluation_periods == 1 && a.period == 300 && a.actions_enabled && a.comparison_operator == "GreaterThanOrEqualToThreshold" && a.statistic == "Sum" && a.treat_missing_data == "notBreaching"
    ])
    error_message = "Each CIS alarm must fire on a single matching event (AU-6, IR-6)."
  }

  assert {
    condition = length(distinct([for a in [
      aws_cloudwatch_metric_alarm.root_usage,
      aws_cloudwatch_metric_alarm.unauthorized_api_calls,
      aws_cloudwatch_metric_alarm.console_signin_without_mfa,
      aws_cloudwatch_metric_alarm.iam_policy_changes,
      aws_cloudwatch_metric_alarm.cloudtrail_config_changes,
      aws_cloudwatch_metric_alarm.console_auth_failures,
      aws_cloudwatch_metric_alarm.cmk_disable_or_delete,
      aws_cloudwatch_metric_alarm.s3_bucket_policy_changes,
      aws_cloudwatch_metric_alarm.config_config_changes,
      aws_cloudwatch_metric_alarm.security_group_changes,
      aws_cloudwatch_metric_alarm.nacl_changes,
      aws_cloudwatch_metric_alarm.network_gateway_changes,
      aws_cloudwatch_metric_alarm.route_table_changes,
      aws_cloudwatch_metric_alarm.vpc_changes,
    ] : a.alarm_name])) == 14
    error_message = "The module must define 14 distinct CIS alarms."
  }
}

run "key_patterns" {
  command = plan

  assert {
    condition     = strcontains(aws_cloudwatch_log_metric_filter.root_usage.pattern, "$.userIdentity.type=\"Root\"") && strcontains(aws_cloudwatch_log_metric_filter.root_usage.pattern, "invokedBy NOT EXISTS")
    error_message = "The root usage filter must match root activity not invoked by an AWS service (CIS 1.7)."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_log_metric_filter.cmk_disable_or_delete.pattern, "DisableKey") && strcontains(aws_cloudwatch_log_metric_filter.cmk_disable_or_delete.pattern, "ScheduleKeyDeletion")
    error_message = "The CMK filter must catch both disabling and scheduling deletion of a key (SC-12)."
  }
}

run "topic_is_encrypted_and_scoped" {
  command = plan

  assert {
    condition     = aws_kms_key.cis_alarms.enable_key_rotation && aws_kms_key.cis_alarms.deletion_window_in_days >= 7 && aws_kms_key.cis_alarms.deletion_window_in_days <= 30
    error_message = "The alarm topic CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.cis_alarms_kms.json).Statement : s if s.Sid == "AllowCloudWatchAlarmsPublish"]).Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "CloudWatch use of the key must be limited to this account (confused deputy)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.cis_alarms_kms.json).Statement : s if s.Sid == "AllowRootAccountAdmin"]).Principal.AWS == "arn:aws-us-gov:iam::123456789012:root"
    error_message = "The key policy must build the root ARN from the current partition."
  }
}

run "alarms_notify_the_encrypted_topic" {
  command = plan

  assert {
    condition = alltrue([
      for a in [
        aws_cloudwatch_metric_alarm.root_usage,
        aws_cloudwatch_metric_alarm.unauthorized_api_calls,
        aws_cloudwatch_metric_alarm.console_signin_without_mfa,
        aws_cloudwatch_metric_alarm.iam_policy_changes,
        aws_cloudwatch_metric_alarm.cloudtrail_config_changes,
        aws_cloudwatch_metric_alarm.console_auth_failures,
        aws_cloudwatch_metric_alarm.cmk_disable_or_delete,
        aws_cloudwatch_metric_alarm.s3_bucket_policy_changes,
        aws_cloudwatch_metric_alarm.config_config_changes,
        aws_cloudwatch_metric_alarm.security_group_changes,
        aws_cloudwatch_metric_alarm.nacl_changes,
        aws_cloudwatch_metric_alarm.network_gateway_changes,
        aws_cloudwatch_metric_alarm.route_table_changes,
        aws_cloudwatch_metric_alarm.vpc_changes,
      ] : a.alarm_actions == toset(["arn:aws-us-gov:sns:us-gov-west-1:123456789012:cis-benchmark-alarms"])
    ])
    error_message = "Every CIS alarm must notify the alarm topic (IR-6)."
  }

  assert {
    condition     = aws_sns_topic.cis_alarms.kms_master_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/cis"
    error_message = "The alarm topic must be encrypted with the module's CMK (SC-28)."
  }
}
