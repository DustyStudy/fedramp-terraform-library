# CloudWatch Logs metric filters and alarms for the 14 detections in the CIS
# AWS Foundations Benchmark (mirrored as AWS Security Hub CSPM controls
# CloudWatch.1 through CloudWatch.14). Filter patterns are copied verbatim
# from AWS's own documentation -- Security Hub CSPM's checks fail if the
# exact prescribed pattern isn't used, so these are not paraphrased or
# simplified.
#
# Deploy against the CloudWatch Logs log group created by
# modules/org-cloudtrail (or any log group receiving CloudTrail management
# events).
#
# Control mapping:
#   Rev5 (Moderate/High): AU-6, AU-6(1), AU-12, SI-4, CA-7, IR-4
#   FedRAMP 20x: KSI-MLA-01 (comprehensive logging), KSI-MLA-04 (continuous
#     security posture monitoring)

resource "aws_sns_topic" "cis_alarms" {
  name              = "cis-benchmark-alarms"
  kms_master_key_id = "alias/aws/sns"
}

data "aws_iam_policy_document" "cis_alarms_topic" {
  statement {
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.cis_alarms.arn]
  }
}

resource "aws_sns_topic_policy" "cis_alarms" {
  arn    = aws_sns_topic.cis_alarms.arn
  policy = data.aws_iam_policy_document.cis_alarms_topic.json
}

# --- RootAccountUsage ---
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "RootAccountUsage"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"

  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "cis-root-account-usage"
  alarm_description   = "Root user activity detected."
  namespace           = "LogMetrics"
  metric_name         = "RootAccountUsage"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- UnauthorizedApiCalls ---
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedApiCalls"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"

  metric_transformation {
    name          = "UnauthorizedApiCalls"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "cis-unauthorized-api-calls"
  alarm_description   = "Unauthorized API call(s) detected."
  namespace           = "LogMetrics"
  metric_name         = "UnauthorizedApiCalls"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- ConsoleSignInWithoutMfa ---
resource "aws_cloudwatch_log_metric_filter" "console_signin_without_mfa" {
  name           = "ConsoleSignInWithoutMfa"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"

  metric_transformation {
    name          = "ConsoleSignInWithoutMfa"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_without_mfa" {
  alarm_name          = "cis-console-signin-without-mfa"
  alarm_description   = "IAM user console sign-in without MFA detected."
  namespace           = "LogMetrics"
  metric_name         = "ConsoleSignInWithoutMfa"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- IamPolicyChanges ---
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IamPolicyChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}"

  metric_transformation {
    name          = "IamPolicyChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "cis-iam-policy-changes"
  alarm_description   = "IAM policy change detected."
  namespace           = "LogMetrics"
  metric_name         = "IamPolicyChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- CloudTrailConfigChanges ---
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_config_changes" {
  name           = "CloudTrailConfigChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"

  metric_transformation {
    name          = "CloudTrailConfigChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_config_changes" {
  alarm_name          = "cis-cloudtrail-config-changes"
  alarm_description   = "CloudTrail configuration change detected."
  namespace           = "LogMetrics"
  metric_name         = "CloudTrailConfigChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- ConsoleAuthFailures ---
resource "aws_cloudwatch_log_metric_filter" "console_auth_failures" {
  name           = "ConsoleAuthFailures"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"

  metric_transformation {
    name          = "ConsoleAuthFailures"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_auth_failures" {
  alarm_name          = "cis-console-auth-failures"
  alarm_description   = "Failed console authentication attempt(s) detected."
  namespace           = "LogMetrics"
  metric_name         = "ConsoleAuthFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- CmkDisableOrScheduledDeletion ---
resource "aws_cloudwatch_log_metric_filter" "cmk_disable_or_delete" {
  name           = "CmkDisableOrScheduledDeletion"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}"

  metric_transformation {
    name          = "CmkDisableOrScheduledDeletion"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cmk_disable_or_delete" {
  alarm_name          = "cis-cmk-disable-or-delete"
  alarm_description   = "Customer managed KMS key disabled or scheduled for deletion."
  namespace           = "LogMetrics"
  metric_name         = "CmkDisableOrScheduledDeletion"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- S3BucketPolicyChanges ---
resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  name           = "S3BucketPolicyChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"

  metric_transformation {
    name          = "S3BucketPolicyChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  alarm_name          = "cis-s3-bucket-policy-changes"
  alarm_description   = "S3 bucket policy or configuration change detected."
  namespace           = "LogMetrics"
  metric_name         = "S3BucketPolicyChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- ConfigConfigurationChanges ---
resource "aws_cloudwatch_log_metric_filter" "config_config_changes" {
  name           = "ConfigConfigurationChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}"

  metric_transformation {
    name          = "ConfigConfigurationChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "config_config_changes" {
  alarm_name          = "cis-config-configuration-changes"
  alarm_description   = "AWS Config configuration change detected."
  namespace           = "LogMetrics"
  metric_name         = "ConfigConfigurationChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- SecurityGroupChanges ---
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "SecurityGroupChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}"

  metric_transformation {
    name          = "SecurityGroupChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "cis-security-group-changes"
  alarm_description   = "Security group change detected."
  namespace           = "LogMetrics"
  metric_name         = "SecurityGroupChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- NaclChanges ---
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  name           = "NaclChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}"

  metric_transformation {
    name          = "NaclChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  alarm_name          = "cis-nacl-changes"
  alarm_description   = "Network ACL change detected."
  namespace           = "LogMetrics"
  metric_name         = "NaclChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- NetworkGatewayChanges ---
resource "aws_cloudwatch_log_metric_filter" "network_gateway_changes" {
  name           = "NetworkGatewayChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}"

  metric_transformation {
    name          = "NetworkGatewayChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gateway_changes" {
  alarm_name          = "cis-network-gateway-changes"
  alarm_description   = "Network gateway change detected."
  namespace           = "LogMetrics"
  metric_name         = "NetworkGatewayChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- RouteTableChanges ---
resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  name           = "RouteTableChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}"

  metric_transformation {
    name          = "RouteTableChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  alarm_name          = "cis-route-table-changes"
  alarm_description   = "Route table change detected."
  namespace           = "LogMetrics"
  metric_name         = "RouteTableChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}

# --- VpcChanges ---
resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  name           = "VpcChanges"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}"

  metric_transformation {
    name          = "VpcChanges"
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  alarm_name          = "cis-vpc-changes"
  alarm_description   = "VPC configuration change detected."
  namespace           = "LogMetrics"
  metric_name         = "VpcChanges"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cis_alarms.arn]
}
