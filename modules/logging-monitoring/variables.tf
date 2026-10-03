variable "cloudtrail_log_group_name" {
  type        = string
  description = "Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail)."
}
