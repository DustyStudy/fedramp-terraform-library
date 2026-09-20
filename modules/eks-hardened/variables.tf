variable "cluster_name" {
  description = "Name of the hardened EKS cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes control plane version"
  type        = string
  default     = "1.30"
}

variable "private_subnet_ids" {
  description = "Private Subnet IDs for the EKS Cluster"
  type        = list(string)
}

variable "log_retention_days" {
  description = "Retention period, in days, for the encrypted EKS control-plane log group"
  type        = number
  default     = 365
}
