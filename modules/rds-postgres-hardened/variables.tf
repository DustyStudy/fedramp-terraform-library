variable "db_name" {
  description = "Database instance identifier"
  type        = string
  default     = "fedramp-postgres-db"
}

variable "instance_class" {
  description = "RDS DB instance compute class"
  type        = string
  default     = "db.r6g.large"
}

variable "allocated_storage" {
  description = "Initial storage in GB"
  type        = number
  default     = 100
}

variable "max_allocated_storage" {
  description = "Upper storage auto-scaling threshold in GB"
  type        = number
  default     = 500
}

variable "admin_username" {
  description = "Master DB username"
  type        = string
  default     = "dbadmin"
}

variable "vpc_id" {
  description = "VPC ID where the database resides"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to communicate with the database"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private isolated subnet IDs across at least 2 Availability Zones"
  type        = list(string)
}

variable "engine_version" {
  description = "PostgreSQL engine version. Give the major version only (for example \"16\") so that automatic minor version upgrades never show as drift; a full \"major.minor\" pins the starting minor version. The parameter group family is derived from the major version"
  type        = string
  default     = "16"

  validation {
    condition     = can(regex("^[1-9][0-9](\\.[0-9]+)?$", var.engine_version))
    error_message = "engine_version must be a PostgreSQL major version such as \"16\", or major.minor such as \"16.9\"."
  }
}

variable "log_retention_days" {
  description = "Retention period, in days, for the encrypted PostgreSQL and upgrade log groups"
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a retention period CloudWatch Logs accepts: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288 or 3653."
  }
}
