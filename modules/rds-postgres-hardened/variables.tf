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
