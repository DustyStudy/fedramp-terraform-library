# Deployable root for modules/iam-access-control. Other roots should call the module
# directly: this root configures its own provider for FIPS endpoints.
module "iam_access_control" {
  source = "../../modules/iam-access-control"

  unused_access_age           = var.unused_access_age
  analyzer_type               = var.analyzer_type
  root_usage_alert_topic_name = var.root_usage_alert_topic_name
}

# Resources lived in this root before 1.3.0.
moved {
  from = aws_kms_key.root_usage_alerts
  to   = module.iam_access_control.aws_kms_key.root_usage_alerts
}

moved {
  from = aws_sns_topic.root_usage_alerts
  to   = module.iam_access_control.aws_sns_topic.root_usage_alerts
}

moved {
  from = aws_sns_topic_policy.root_usage_alerts
  to   = module.iam_access_control.aws_sns_topic_policy.root_usage_alerts
}

moved {
  from = aws_accessanalyzer_analyzer.external_access
  to   = module.iam_access_control.aws_accessanalyzer_analyzer.external_access
}

moved {
  from = aws_accessanalyzer_analyzer.unused_access
  to   = module.iam_access_control.aws_accessanalyzer_analyzer.unused_access
}

moved {
  from = aws_iam_group.require_mfa
  to   = module.iam_access_control.aws_iam_group.require_mfa
}

moved {
  from = aws_iam_group_policy.require_mfa
  to   = module.iam_access_control.aws_iam_group_policy.require_mfa
}

moved {
  from = aws_cloudwatch_event_rule.root_usage
  to   = module.iam_access_control.aws_cloudwatch_event_rule.root_usage
}

moved {
  from = aws_cloudwatch_event_target.root_usage
  to   = module.iam_access_control.aws_cloudwatch_event_target.root_usage
}

moved {
  from = aws_iam_policy.developer_permission_boundary
  to   = module.iam_access_control.aws_iam_policy.developer_permission_boundary
}
