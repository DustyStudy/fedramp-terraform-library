variable "cluster_name" {
  description = "Name of the ECS Cluster"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Log retention in days (FedRAMP requires >= 365)"
  type        = number
  default     = 365
}
