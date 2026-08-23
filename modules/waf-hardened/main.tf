locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS CMK for WAF Logging
data "aws_iam_policy_document" "waf_kms" {
  #checkov:skip=CKV_AWS_109:KMS root account scoping
  #checkov:skip=CKV_AWS_111:KMS key management write access
  #checkov:skip=CKV_AWS_356:KMS key policy wildcard scoping
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Required: CloudWatch Logs makes its own encrypt/decrypt calls as the
  # logs service, not as the IAM principal that created the log group.
  # Without this statement, log delivery to a KMS-encrypted log group
  # fails outright — this isn't optional hardening, it's how CloudWatch
  # Logs KMS encryption works at all.
  statement {
    sid    = "AllowCloudWatchLogsEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "waf" {
  description             = "KMS Key for WAF CloudWatch Log Group"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.waf_kms.json
}

# CloudWatch Log Group for WAF (Must start with aws-waf-logs-)
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.waf.arn
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.environment}-fedramp-waf-acl"
  description = "FedRAMP SC-5 / SI-3 Compliant Web ACL with OWASP Core Rules and Rate Limiting"
  scope       = var.scope

  default_action {
    allow {}
  }

  # 1. AWS Managed Common Rule Set (OWASP Top 10)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # 2. AWS Managed Known Bad Inputs Rule Set
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }

  # 3. AWS Managed IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IpReputationMetric"
      sampled_requests_enabled   = true
    }
  }

  # 4. Rate-Based DoS Mitigation (SC-5)
  rule {
    name     = "RateLimitPerIp"
    priority = 40

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_threshold
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.environment}-waf-overall-metrics"
    sampled_requests_enabled   = true
  }
}

# Attach Logging Configuration (AU-2 / AU-12 / CKV2_AWS_31)
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn
}
