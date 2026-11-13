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

variable "enable_dns_firewall" {
  description = "Attach a Route 53 Resolver DNS Firewall rule group to the VPC that blocks dns_firewall_blocked_domains."
  type        = bool
  default     = false
}

variable "dns_firewall_blocked_domains" {
  description = "Domains the DNS Firewall answers with NXDOMAIN. A leading *. matches subdomains only, so list the apex too. The default is GSocket's relay network ([a-z].gs.thc.org) and its download hosts (gsocket.io)."
  type        = list(string)
  default     = ["gs.thc.org", "*.gs.thc.org", "gsocket.io", "*.gsocket.io"]

  validation {
    condition     = length(var.dns_firewall_blocked_domains) > 0
    error_message = "dns_firewall_blocked_domains must list at least one domain."
  }
}

variable "dns_firewall_mutation_protection" {
  description = "Stop the DNS Firewall association from being changed or removed. AWS refuses to remove a protected association, so to turn the firewall off or destroy the module, apply with this set to false first."
  type        = bool
  default     = true
}
