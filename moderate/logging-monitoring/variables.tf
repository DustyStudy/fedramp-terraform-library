variable "cloudtrail_log_group_name" {
  type        = string
  description = "Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail)."
}

variable "expected_secret_readers" {
  type        = list(string)
  description = "Principal ARNs (userIdentity.arn, one * wildcard each) that normally read secrets and SSM parameters. When non-empty, reads by any other principal raise an alarm. Empty (default) creates no secret-read alarm."
  default     = []
}
