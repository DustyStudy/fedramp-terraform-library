variable "environment" {
  type    = string
  default = "fedramp"
}

variable "vpc_cidr" {
  type    = string
  default = "10.100.0.0/16"
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.1.0/24", "10.100.2.0/24"]
}

variable "app_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.10.0/24", "10.100.20.0/24"]
}

variable "db_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.100.0/24", "10.100.200.0/24"]
}

variable "log_retention_days" {
  type    = number
  default = 365
}
