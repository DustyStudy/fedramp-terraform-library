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
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

override_resource {
  target          = aws_kms_key.waf
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/waf"
  }
}

run "managed_rule_groups_block" {
  command = plan

  assert {
    condition = toset(flatten([
      for r in aws_wafv2_web_acl.this.rule : [for m in r.statement[0].managed_rule_group_statement : m.name]
      ])) == toset([
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet",
      "AWSManagedRulesSQLiRuleSet",
      "AWSManagedRulesAmazonIpReputationList",
    ])
    error_message = "The web ACL must use the common, known-bad-inputs, SQL injection and IP reputation rule groups (SC-7, SI-3, SI-10)."
  }

  assert {
    condition = alltrue([
      for r in aws_wafv2_web_acl.this.rule :
      length(r.override_action[0].none) == 1 && length(r.statement[0].managed_rule_group_statement[0].rule_action_override) == 0 && r.statement[0].managed_rule_group_statement[0].vendor_name == "AWS"
      if length(r.statement[0].managed_rule_group_statement) > 0
    ])
    error_message = "Managed rule groups must keep their own block actions, not be overridden to count."
  }

  assert {
    condition     = length(distinct([for r in aws_wafv2_web_acl.this.rule : r.priority])) == length(aws_wafv2_web_acl.this.rule)
    error_message = "Rule priorities must be unique."
  }
}

run "rate_limit_blocks_per_ip" {
  command = plan

  variables {
    rate_limit_threshold = 500
  }

  assert {
    condition     = one([for r in aws_wafv2_web_acl.this.rule : r.statement[0].rate_based_statement[0].limit if r.name == "RateLimitPerIp"]) == 500 && one([for r in aws_wafv2_web_acl.this.rule : r.statement[0].rate_based_statement[0].aggregate_key_type if r.name == "RateLimitPerIp"]) == "IP"
    error_message = "The rate limit must follow rate_limit_threshold (SC-5)."
  }

  assert {
    condition     = length(one([for r in aws_wafv2_web_acl.this.rule : r.action[0].block if r.name == "RateLimitPerIp"])) == 1
    error_message = "Requests over the rate limit must be blocked."
  }
}

run "logging_redacts_credentials" {
  command = plan

  assert {
    condition     = !aws_wafv2_web_acl.this.visibility_config[0].sampled_requests_enabled && alltrue([for r in aws_wafv2_web_acl.this.rule : !r.visibility_config[0].sampled_requests_enabled])
    error_message = "Request sampling must be off: sampled requests keep the Authorization and Cookie headers that logging redacts (SC-28)."
  }

  assert {
    condition     = toset([for f in aws_wafv2_web_acl_logging_configuration.this.redacted_fields : f.single_header[0].name]) == toset(["authorization", "cookie"])
    error_message = "WAF logs must redact the Authorization and Cookie headers (AU-9, SC-28)."
  }

  assert {
    condition     = startswith(aws_cloudwatch_log_group.waf.name, "aws-waf-logs-") && aws_cloudwatch_log_group.waf.retention_in_days >= 365
    error_message = "WAF can only log to a group named aws-waf-logs-*, kept at least 365 days (AU-11)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.waf.kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/waf"
    error_message = "WAF logs must be encrypted with the module's CMK (SC-28)."
  }

  assert {
    condition     = aws_kms_key.waf.enable_key_rotation && aws_kms_key.waf.deletion_window_in_days >= 7 && aws_kms_key.waf.deletion_window_in_days <= 30
    error_message = "The WAF log CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }
}
