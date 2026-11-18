variable "cluster_name" {
  description = "Name of the hardened EKS cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes control plane minor version, e.g. 1.36. EKS upgrades one minor version at a time. Keep it inside EKS standard support: with support_type STANDARD, AWS upgrades the control plane itself once the version leaves it."
  type        = string
  default     = "1.36"

  validation {
    condition     = can(regex("^1\\.[0-9]{2}$", var.kubernetes_version))
    error_message = "kubernetes_version must be a minor version such as 1.36 (no patch level, no leading v)."
  }
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

variable "authentication_mode" {
  description = "Cluster authentication mode: API (access entries only), API_AND_CONFIG_MAP, or CONFIG_MAP. One-way: a cluster can move CONFIG_MAP -> API_AND_CONFIG_MAP -> API but never back. API ignores the aws-auth ConfigMap, so move an existing cluster to API_AND_CONFIG_MAP first and migrate its mappings to access entries."
  type        = string
  default     = "API"

  validation {
    condition     = contains(["API", "API_AND_CONFIG_MAP", "CONFIG_MAP"], var.authentication_mode)
    error_message = "authentication_mode must be API, API_AND_CONFIG_MAP or CONFIG_MAP."
  }
}

variable "bootstrap_cluster_creator_admin_permissions" {
  description = "Give the principal that creates the cluster cluster-admin. Only read at cluster creation; changes afterwards are ignored (the provider would otherwise replace the cluster)."
  type        = bool
  default     = true
}

variable "cluster_admin_principal_arns" {
  description = "IAM role or user ARNs granted AmazonEKSClusterAdminPolicy on the whole cluster through access entries, so access does not depend on the principal that created the cluster. Requires authentication_mode API or API_AND_CONFIG_MAP. ARNs must be known at plan time."
  type        = set(string)
  default     = []
}

variable "support_type" {
  description = "EKS upgrade policy. STANDARD: no extended support charges; AWS automatically upgrades the control plane when its version reaches end of standard support. EXTENDED: the cluster may stay on the version for 12 more months at the extended support price."
  type        = string
  default     = "STANDARD"

  validation {
    condition     = contains(["STANDARD", "EXTENDED"], var.support_type)
    error_message = "support_type must be STANDARD or EXTENDED."
  }
}
