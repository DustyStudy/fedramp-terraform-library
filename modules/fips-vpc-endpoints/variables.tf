variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "fedramp"
}

variable "vpc_id" {
  description = "VPC ID where endpoints will be provisioned"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block allowed to communicate with endpoints"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for Interface Endpoints (must be private/isolated)"
  type        = list(string)
}

variable "route_table_ids" {
  description = "Route table IDs for S3 Gateway Endpoint"
  type        = list(string)
}

variable "fips_endpoint_services" {
  description = "List of core AWS services requiring FIPS endpoints"
  type        = list(string)
  default = [
    "kms",
    "secretsmanager",
    "ssm",
    "ssmmessages",
    "ec2",
    "ec2messages",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts",
    "monitoring"
  ]
}
