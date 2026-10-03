# Deployable root for modules/logging-monitoring. Other roots should call the module
# directly: this root configures its own provider for FIPS endpoints.
module "logging_monitoring" {
  source = "../../modules/logging-monitoring"

  cloudtrail_log_group_name = var.cloudtrail_log_group_name
}

# Resources lived in this root before 1.3.0.
moved {
  from = aws_kms_key.cis_alarms
  to   = module.logging_monitoring.aws_kms_key.cis_alarms
}

moved {
  from = aws_sns_topic.cis_alarms
  to   = module.logging_monitoring.aws_sns_topic.cis_alarms
}

moved {
  from = aws_sns_topic_policy.cis_alarms
  to   = module.logging_monitoring.aws_sns_topic_policy.cis_alarms
}

moved {
  from = aws_cloudwatch_log_metric_filter.root_usage
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.root_usage
}

moved {
  from = aws_cloudwatch_metric_alarm.root_usage
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.root_usage
}

moved {
  from = aws_cloudwatch_log_metric_filter.unauthorized_api_calls
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.unauthorized_api_calls
}

moved {
  from = aws_cloudwatch_metric_alarm.unauthorized_api_calls
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.unauthorized_api_calls
}

moved {
  from = aws_cloudwatch_log_metric_filter.console_signin_without_mfa
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.console_signin_without_mfa
}

moved {
  from = aws_cloudwatch_metric_alarm.console_signin_without_mfa
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.console_signin_without_mfa
}

moved {
  from = aws_cloudwatch_log_metric_filter.iam_policy_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.iam_policy_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.iam_policy_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.iam_policy_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.cloudtrail_config_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.cloudtrail_config_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.cloudtrail_config_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.cloudtrail_config_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.console_auth_failures
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.console_auth_failures
}

moved {
  from = aws_cloudwatch_metric_alarm.console_auth_failures
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.console_auth_failures
}

moved {
  from = aws_cloudwatch_log_metric_filter.cmk_disable_or_delete
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.cmk_disable_or_delete
}

moved {
  from = aws_cloudwatch_metric_alarm.cmk_disable_or_delete
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.cmk_disable_or_delete
}

moved {
  from = aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.s3_bucket_policy_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.s3_bucket_policy_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.config_config_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.config_config_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.config_config_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.config_config_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.security_group_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.security_group_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.security_group_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.security_group_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.nacl_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.nacl_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.nacl_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.nacl_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.network_gateway_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.network_gateway_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.network_gateway_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.network_gateway_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.route_table_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.route_table_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.route_table_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.route_table_changes
}

moved {
  from = aws_cloudwatch_log_metric_filter.vpc_changes
  to   = module.logging_monitoring.aws_cloudwatch_log_metric_filter.vpc_changes
}

moved {
  from = aws_cloudwatch_metric_alarm.vpc_changes
  to   = module.logging_monitoring.aws_cloudwatch_metric_alarm.vpc_changes
}
