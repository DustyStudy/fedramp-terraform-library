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
