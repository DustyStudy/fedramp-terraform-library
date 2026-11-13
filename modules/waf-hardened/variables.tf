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
