variable "environment" {
  type    = string
  default = "fedramp"
}

variable "scope" {
  type        = string
  default     = "REGIONAL"
  description = "REGIONAL for ALB/API Gateway or CLOUDFRONT for edge distribution"
}

variable "rate_limit_threshold" {
  type        = number
  default     = 2000
  description = "Maximum requests allowed from a single IP per 5-minute window"
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Retention period for WAF logs in days"
}

variable "enable_sqli_rule_set" {
  type        = bool
  default     = true
  description = "Add the AWS managed SQL injection rule group (AWSManagedRulesSQLiRuleSet, 200 WCU), which blocks requests that look like SQL injection (SI-10). Test it against your traffic before production; set false if your app has no SQL backend or you filter SQLi elsewhere."
}

variable "rule_action_overrides" {
  type        = map(list(string))
  default     = {}
  description = "Rules inside a managed rule group to switch from block to count, keyed by rule group name, e.g. { AWSManagedRulesCommonRuleSet = [\"SizeRestrictions_BODY\"] } for apps that take request bodies over 8 KB (uploads, large JSON). A counted rule still shows in metrics and logs but no longer blocks, so record each override as a deviation and cover the gap another way (SI-10)."

  validation {
    condition = alltrue([for g in keys(var.rule_action_overrides) : contains([
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet",
      "AWSManagedRulesSQLiRuleSet",
      "AWSManagedRulesAmazonIpReputationList",
    ], g)])
    error_message = "rule_action_overrides keys must be rule groups this module deploys: AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesAmazonIpReputationList."
  }
}
